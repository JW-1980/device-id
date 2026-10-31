<?php

declare(strict_types=1);

namespace DeviceId\Model;

use DeviceId\Email\EmailAssessment;
use DeviceId\Network\NetworkFacts;
use DeviceId\Scoring\ScoredClaims;

/**
 * Builds the de-identified training row a host stores for a scored visit (GDPR data
 * minimisation, Art. 5(1)(c)): a feature vector, a label and bucketed context, with its
 * retention period as metadata. It is the ONLY shape the trainer accepts from a host.
 *
 * ## What a row contains
 *
 * - `features`: names and numbers from {@see FeatureCatalogue}: which rules fired, never what
 *   the browser reported. Coverage is bucketed to five levels before it becomes a feature.
 * - `group`: a KEYED hash of the device key (HMAC-SHA256 under the host's training secret,
 *   truncated to 16 hex characters). It exists only so a train/validation split can keep one
 *   device on one side; it cannot be reversed to the device key without the secret, and
 *   rotating the secret severs it. It is pseudonymous data and is treated as such.
 * - `observed_week` (ISO year-week) instead of a date or time, `slice` buckets (engine family,
 *   mobile or desktop, protected mode), `rules_weight`.
 * - `network`: the country code the address geolocates to and a category bucket of its network
 *   (`hosting`, `vpn`, `tor`, `other`, `unknown`); never the address or the ASN number. A country is
 *   a 2-letter bucket of millions of people; the host's k-floor applies when it is sliced on.
 * - `email`: three buckets about the sign-up address (`domain_class` disposable, forwarding, free,
 *   other, unknown or invalid; `mx` ok, no_mail or unknown; `generated` none, possible or likely),
 *   never the address, its domain or a hash of either. The e-mail, novelty and velocity facts are
 *   also features (names and numbers only).
 * - `retention_days` and `expires_on`: the host's pruning job deletes the row on that date.
 *
 * ## What it never contains
 *
 * No IP address or network token, no User-Agent or any token of it, no brand or version
 * string, no account or user id, no device key, no timestamp finer than a week, no component
 * value. {@see assertDeidentified()} checks a row against that and the host should call it
 * before insert; the tests pin that the builder cannot emit them.
 */
final class TrainingRowBuilder
{
    public const DEFAULT_RETENTION_DAYS = 365;

    private const ALLOWED_KEYS = ['id', 'features', 'label', 'label_weight', 'source', 'group', 'slice', 'rules_weight', 'observed_week', 'retention_days', 'expires_on', 'schema', 'network', 'email'];

    public function __construct(private readonly string $secret, private readonly int $retentionDays = self::DEFAULT_RETENTION_DAYS)
    {
        if (strlen($secret) < 32) {
            throw new \InvalidArgumentException('the training secret must be at least 32 characters');
        }
    }

    /**
     * @param  string  $deviceKey  hashed into `group`, never stored
     * @param  string  $engine  chromium|gecko|webkit|unknown
     * @param  array<string, float>  $softFeatures  the optional features ({@see FeatureCatalogue::optional()}): reputation, network, smart signals, velocity
     * @param  NetworkFacts|null  $network  reduced to a country code and an ASN category bucket; the address and the ASN number never enter the row
     * @param  EmailAssessment|null  $email  reduced to three buckets; the address and its domain never enter the row
     * @return array<string, mixed> JSON-ready, see the class docblock
     */
    public function build(ScoredClaims $scored, string $deviceKey, string $engine, bool $mobile, bool $protected, ?string $label, string $labelSource, float $labelWeight, \DateTimeImmutable $observedAt, array $softFeatures = [], ?NetworkFacts $network = null, ?EmailAssessment $email = null): array
    {
        $omitted = 0;
        foreach ($scored->omission as $entry) {
            $omitted += count($entry['omitted'] ?? []);
        }

        $features = FeatureCatalogue::build(
            $scored->verdict->disagreements,
            $scored->integrityCount,
            self::bucketCoverage($scored->confidence->score),
            count($scored->untrusted),
            $omitted,
            $protected,
            $softFeatures,
        );

        $row = [
            'schema' => 1,
            'id' => bin2hex(random_bytes(8)),
            'features' => $features,
            'label' => $label,
            'label_weight' => max(0.0, min(1.0, $labelWeight)),
            'source' => $labelSource,
            'group' => substr(hash_hmac('sha256', $deviceKey, $this->secret), 0, 16),
            'slice' => [
                'engine' => in_array($engine, ['chromium', 'gecko', 'webkit'], true) ? $engine : 'unknown',
                'device' => $mobile ? 'mobile' : 'desktop',
                'privacy' => $protected ? 'protected' : 'none',
            ],
            'network' => $network?->trainingBuckets() ?? ['country' => 'unknown', 'asn_category' => 'unknown'],
            'email' => $email?->trainingBuckets() ?? ['domain_class' => EmailAssessment::CLASS_UNKNOWN, 'mx' => 'unknown', 'generated' => 'none'],
            'rules_weight' => $scored->verdict->totalWeight(),
            'observed_week' => $observedAt->format('o-\WW'),
            'retention_days' => $this->retentionDays,
            'expires_on' => $observedAt->modify('+'.$this->retentionDays.' days')->format('Y-m-d'),
        ];

        self::assertDeidentified($row);

        return $row;
    }

    /**
     * Coverage 0-100 in five buckets (the nearest of 10, 30, 50, 70, 90).
     */
    public static function bucketCoverage(int $score): int
    {
        return (int) (min(4, intdiv(max(0, min(100, $score)), 20)) * 20 + 10);
    }

    /**
     * Throws when a row carries a key outside the allow-list or a string that looks like an
     * address, a User-Agent or an identifier.
     *
     * @param  array<array-key, mixed>  $row
     */
    public static function assertDeidentified(array $row): void
    {
        foreach (array_keys($row) as $key) {
            if (! in_array($key, self::ALLOWED_KEYS, true)) {
                throw new \UnexpectedValueException("training row key '{$key}' is not on the allow-list");
            }
        }
        $leaves = [];
        array_walk_recursive($row, static function (mixed $value, mixed $key) use (&$leaves): void {
            $leaves[] = (string) $key;
            if (is_string($value)) {
                $leaves[] = $value;
            }
        });
        foreach ($leaves as $text) {
            if (filter_var($text, FILTER_VALIDATE_IP) !== false
                || preg_match('/Mozilla\/|AppleWebKit|Gecko\/|HeadlessChrome|@[a-z0-9-]+\.[a-z]{2,}/i', $text) === 1
                || preg_match('/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i', $text) === 1) {
                throw new \UnexpectedValueException('a training row carries a value that looks like an address, a User-Agent, an email or a domain');
            }
        }
    }
}

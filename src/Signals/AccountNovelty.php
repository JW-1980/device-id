<?php

declare(strict_types=1);

namespace DeviceId\Signals;

use DeviceId\Model\FeatureCatalogue;
use DeviceId\Network\NetworkFacts;
use DeviceId\Reasons\ReasonCatalogue;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;

/**
 * Account novelty (Castle's `new_device`, `new_country`, `new_isp`, `new_language`, `new_os`): the
 * first time an ACCOUNT is seen with a device, country, network, language or operating system.
 * A pure function over the history the host selects from its own tables; nothing is stored here.
 *
 * ## Rules that keep it quiet
 *
 * - **Never on the first observation.** An account with no usable history has no baseline, so
 *   nothing about it is "new" ({@see $firstObservation}). The same goes for one dimension that no
 *   history entry knows (a country that was never resolved): unknown stays unknown.
 * - **A value is known after one trusted visit.** The host appends an observation once the visit
 *   was accepted (it passed or answered a challenge); `trusted: false` entries (a refused visit, a
 *   hijacked session found later) never become part of the baseline, so an attacker cannot teach
 *   the account his own device.
 * - **Anonymised networks say nothing about the person.** An observation through a VPN, proxy,
 *   hosting or Tor address (`anonymised: true`) takes no part in the country and network baselines
 *   and, as the current visit, raises neither `new_country` nor `new_asn` (the same rule as impossible travel).
 * - **Old history expires.** Entries older than `fingerprint.novelty.history_days` (365) are
 *   ignored.
 * - Nothing here scores or blocks. Together `new_device` and `new_country` set
 *   {@see $suggestsStepUp}: a reason to ask for a challenge before a sensitive action (a vote with
 *   weight, publishing a review), not to refuse. FP risk: a new phone, a trip, a new home network.
 *
 * Observation shape (both history and current): `device_key` (string), `country` (ISO alpha-2),
 * `asn` (int), `language` (primary subtag, lower case), `os` (family: windows, macos, linux,
 * android, ios), all optional; history entries also `at` (unix time), `trusted` (default true),
 * `anonymised` (default false).
 */
final readonly class AccountNovelty
{
    public const NEW_DEVICE = 'acct_new_device';

    public const NEW_COUNTRY = 'acct_new_country';

    public const NEW_ASN = 'acct_new_asn';

    public const NEW_LANGUAGE = 'acct_new_language';

    public const NEW_OS = 'acct_new_os';

    private const DIMENSIONS = [
        'device_key' => self::NEW_DEVICE,
        'country' => self::NEW_COUNTRY,
        'asn' => self::NEW_ASN,
        'language' => self::NEW_LANGUAGE,
        'os' => self::NEW_OS,
    ];

    /**
     * @param  list<string>  $new  the `acct_new_*` codes that hold
     * @param  list<string>  $known  `device_key` / `country` dimensions the account HAS shown before (for the lowering reasons)
     */
    public function __construct(
        public bool $firstObservation,
        public array $new = [],
        public array $known = [],
        public bool $suggestsStepUp = false,
    ) {}

    /**
     * @param  list<array<string, mixed>>  $history  the account's earlier observations, any order
     * @param  array<string, mixed>  $current  this visit's observation
     */
    public static function assess(array $history, array $current, ?int $now = null): self
    {
        $now ??= time();
        $horizon = $now - max(1, Config::int('fingerprint.novelty.history_days', 365)) * 86400;

        $baseline = [];
        $usable = 0;
        foreach ($history as $entry) {
            if (! is_array($entry) || ($entry['trusted'] ?? true) === false) {
                continue;
            }
            if (is_int($entry['at'] ?? null) && ($entry['at'] < $horizon || $entry['at'] > $now)) {
                continue;
            }
            $usable++;
            $anonymised = ($entry['anonymised'] ?? false) === true;
            foreach (array_keys(self::DIMENSIONS) as $dimension) {
                if ($anonymised && in_array($dimension, ['country', 'asn'], true)) {
                    continue;
                }
                $value = self::clean($dimension, $entry[$dimension] ?? null);
                if ($value !== null) {
                    $baseline[$dimension][$value] = true;
                }
            }
        }
        if ($usable === 0) {
            return new self(true);
        }

        $currentAnonymised = ($current['anonymised'] ?? false) === true;
        $new = $known = [];
        foreach (self::DIMENSIONS as $dimension => $code) {
            $value = self::clean($dimension, $current[$dimension] ?? null);
            if ($value === null || ($currentAnonymised && in_array($dimension, ['country', 'asn'], true)) || ! isset($baseline[$dimension])) {
                continue;
            }
            if (isset($baseline[$dimension][$value])) {
                $known[] = $dimension;
            } else {
                $new[] = $code;
            }
        }

        return new self(false, $new, $known, in_array(self::NEW_DEVICE, $new, true) && in_array(self::NEW_COUNTRY, $new, true));
    }

    /**
     * Model features ({@see FeatureCatalogue::NOVELTY}); only those that hold.
     *
     * @return array<string, float>
     */
    public function features(): array
    {
        return array_fill_keys($this->new, 1.0);
    }

    /**
     * Reason codes with their direction ({@see ReasonCatalogue}): the new values raise, a device or
     * country the account has shown before lowers.
     *
     * @return list<array{code: string, direction: string}>
     */
    public function reasons(): array
    {
        $out = [];
        foreach ($this->new as $code) {
            $out[] = ['code' => $code, 'direction' => ReasonCatalogue::RAISES];
        }
        foreach ($this->known as $dimension) {
            if ($dimension === 'device_key') {
                $out[] = ['code' => 'acct_known_device', 'direction' => ReasonCatalogue::LOWERS];
            } elseif ($dimension === 'country') {
                $out[] = ['code' => 'acct_known_country', 'direction' => ReasonCatalogue::LOWERS];
            }
        }

        return $out;
    }

    /**
     * This visit's observation from what the engine already has: the device key, the claims (the
     * browser language and the operating system family of the User-Agent) and the network facts.
     * `anonymised` is true for a VPN, hosting or Tor address.
     *
     * @param  array<array-key, mixed>  $claims
     * @return array{device_key: string|null, country: string|null, asn: int|null, language: string|null, os: string|null, anonymised: bool}
     */
    public static function observationFrom(?string $deviceKey, array $claims, ?NetworkFacts $network = null): array
    {
        $language = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'language');
        $ua = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'userAgent');
        $os = is_string($ua) ? EnvironmentConsistency::uaOsFamily($ua) : null;

        return [
            'device_key' => $deviceKey,
            'country' => $network?->country,
            'asn' => $network?->asn,
            'language' => is_string($language) ? self::clean('language', $language) : null,
            'os' => is_string($os) ? $os : null,
            'anonymised' => $network !== null && ($network->isVpn() || $network->isHosting() || $network->torExit),
        ];
    }

    private static function clean(string $dimension, mixed $value): string|int|null
    {
        return match ($dimension) {
            'asn' => is_int($value) && $value > 0 ? $value : null,
            'country' => is_string($value) && preg_match('/^[A-Za-z]{2}$/', $value) === 1 ? strtoupper($value) : null,
            'language' => is_string($value) && preg_match('/^([A-Za-z]{2,3})(?:[-_].*)?$/', $value, $m) === 1 ? strtolower($m[1]) : null,
            'os' => is_string($value) && $value !== '' ? strtolower($value) : null,
            default => is_string($value) && $value !== '' ? $value : null,
        };
    }
}

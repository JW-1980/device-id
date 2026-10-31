<?php

declare(strict_types=1);

namespace DeviceId\Model;

use DeviceId\CheckRegistry;
use DeviceId\Network\NetworkFacts;
use DeviceId\Reputation\ReputationResult;
use DeviceId\Signals\SmartSignals;
use DeviceId\Signals\Velocity;

/**
 * The names a model may use, and the one function that turns a scored visit into them.
 *
 * ## What is a feature, and what is deliberately not
 *
 * Features are facts the client did not type: which rules fired (one indicator per
 * {@see CheckRegistry} code, plus one catch-all for a code the registry does not list), how
 * many distinct rule families fired, how many integrity findings were paid for, how much of
 * the measurement surface answered (coverage), how many components the evidence made
 * untrusted, how many probes were omitted, and whether the visit is a protected privacy mode
 * (so the model can learn NOT to penalise it).
 *
 * Excluded on purpose: the User-Agent and every token in it (a model that sees "Googlebot" or
 * "HeadlessChrome" learns the label, not the behaviour; the rule that reads the token is
 * already a feature), brands, claimed OS strings, raw component values, any network token,
 * any identifier. {@see EXCLUDED} documents the list and a test pins that none is a feature.
 *
 * A weight-0 (silenced) rule is not in the emitted disagreements, so it is 0 here too: the
 * operator's switch-off silences the feature as well.
 */
final class FeatureCatalogue
{
    public const HIT_PREFIX = 'hit:';

    public const UNLISTED_HIT = 'hit:unlisted_code';

    /** What a feature vector never contains. */
    public const EXCLUDED = ['user_agent', 'user_agent_summary', 'brands', 'claimed_os', 'crawler_declaration', 'raw_component', 'ip', 'network_token', 'user_id', 'device_key'];

    /** Soft IP-reputation features ({@see ReputationResult::features()}); absent means no signal. */
    public const REPUTATION = ['rep_datacenter', 'rep_tor_exit', 'rep_abuse_listed'];

    /** Soft network features ({@see NetworkFacts::features()}); absent means no signal. */
    public const NETWORK = ['net_hosting', 'net_vpn', 'net_tor_exit', 'net_history_bad'];

    /**
     * Soft environment features ({@see SmartSignals::features()}): how many of the
     * two locale settings (time zone, languages) disagree with the IP country (0-2), a hypervisor
     * GPU, a default VM screen size, a software GPU, an Android emulator, and private browsing
     * (1 when the engine evidence is medium, 0.5 when low). None of them is a verdict.
     */
    public const SIGNALS = ['sig_locale_disagreements', 'sig_vm_gpu', 'sig_vm_screen', 'sig_software_gpu', 'sig_emulator', 'sig_private_mode'];

    /** Velocity features ({@see Velocity::features()}). */
    public const VELOCITY = ['vel_burst', 'vel_impossible_travel'];

    /** Caps that keep one outlier from dominating a coefficient. */
    private const INTEGRITY_CAP = 5;

    private const UNTRUSTED_CAP = 6;

    private const OMISSION_CAP = 6;

    /**
     * @return list<string>
     */
    public static function names(): array
    {
        $names = [];
        foreach (CheckRegistry::codes() as $code) {
            $names[] = self::HIT_PREFIX.$code;
        }
        $names[] = self::UNLISTED_HIT;
        array_push($names, 'family_count', 'integrity_count', 'coverage', 'untrusted_count', 'omission_count', 'protected', ...self::optional());

        return $names;
    }

    /**
     * The optional, host-supplied soft features: reputation, network, signals, velocity.
     *
     * @return list<string>
     */
    public static function optional(): array
    {
        return [...self::REPUTATION, ...self::NETWORK, ...self::SIGNALS, ...self::VELOCITY];
    }

    public static function knows(string $name): bool
    {
        if (in_array($name, ['family_count', 'integrity_count', 'coverage', 'untrusted_count', 'omission_count', 'protected', self::UNLISTED_HIT, ...self::optional()], true)) {
            return true;
        }

        return str_starts_with($name, self::HIT_PREFIX) && CheckRegistry::isKnown(substr($name, strlen(self::HIT_PREFIX)));
    }

    /**
     * Whether a feature is a rule hit (its coefficient may not be negative: a contradiction
     * is never evidence of honesty).
     */
    public static function isRuleHit(string $name): bool
    {
        return str_starts_with($name, self::HIT_PREFIX);
    }

    /**
     * @param  list<array{code: string, detail?: string, weight: int}>  $disagreements  the EMITTED disagreements (weight above 0)
     * @param  int  $integrityCount  effective integrity findings this visit paid for
     * @param  int|null  $coverageScore  the confidence score 0-100, or null when unknown
     * @param  int  $untrustedCount  components the evidence made untrusted
     * @param  int  $omissionCount  probes the omission gate counted as omitted
     * @param  bool  $protected  a protected privacy mode (Firefox resistFingerprinting, Tor Browser)
     * @param  array<string, float>  $reputation  the optional soft features ({@see optional()}): {@see ReputationResult::features()}, network facts, smart signals, velocity
     * @return array<string, float> only the non-zero features
     */
    public static function build(array $disagreements, int $integrityCount = 0, ?int $coverageScore = null, int $untrustedCount = 0, int $omissionCount = 0, bool $protected = false, array $reputation = []): array
    {
        $features = [];
        $families = [];
        foreach ($disagreements as $disagreement) {
            $code = $disagreement['code'] ?? '';
            if (! is_string($code) || $code === 'model_adjustment' || ($disagreement['weight'] ?? 0) <= 0) {
                continue;
            }
            if (CheckRegistry::isKnown($code)) {
                $features[self::HIT_PREFIX.$code] = 1.0;
                $families[CheckRegistry::familyOf($code) ?? 'unknown'] = true;
            } else {
                $features[self::UNLISTED_HIT] = 1.0;
                $families[str_starts_with($code, 'transport_') ? 'transport' : 'unknown'] = true;
            }
        }

        $extras = [
            'family_count' => (float) count($families),
            'integrity_count' => (float) min(self::INTEGRITY_CAP, max(0, $integrityCount)),
            'coverage' => $coverageScore === null ? 0.0 : max(0, min(100, $coverageScore)) / 100.0,
            'untrusted_count' => (float) min(self::UNTRUSTED_CAP, max(0, $untrustedCount)),
            'omission_count' => (float) min(self::OMISSION_CAP, max(0, $omissionCount)),
            'protected' => $protected ? 1.0 : 0.0,
        ];
        foreach ($extras as $name => $value) {
            if ($value !== 0.0) {
                $features[$name] = $value;
            }
        }

        foreach (self::optional() as $name) {
            $value = $reputation[$name] ?? 0.0;
            if (! is_numeric($value) || $value <= 0.0) {
                continue;
            }
            $features[$name] = match ($name) {
                'sig_locale_disagreements' => min(2.0, (float) $value),
                'sig_private_mode' => min(1.0, (float) $value),
                default => 1.0,
            };
        }

        ksort($features);

        return $features;
    }

    /**
     * Distinct rule families among emitted disagreements, by {@see CheckRegistry::familyOf()}
     * ($code not in the registry counts as `transport` when it starts `transport_`).
     *
     * @param  list<array{code: string, weight: int}>  $disagreements
     * @return list<string>
     */
    public static function families(array $disagreements): array
    {
        $families = [];
        foreach ($disagreements as $disagreement) {
            if (($disagreement['weight'] ?? 0) <= 0 || ! is_string($disagreement['code'] ?? null)) {
                continue;
            }
            $code = $disagreement['code'];
            $family = CheckRegistry::familyOf($code) ?? (str_starts_with($code, 'transport_') ? 'transport' : null);
            if ($family !== null) {
                $families[$family] = true;
            }
        }
        $out = array_keys($families);
        sort($out);

        return $out;
    }
}

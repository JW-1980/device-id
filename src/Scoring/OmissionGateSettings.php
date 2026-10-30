<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Scoring;

use NutriCompare\Fingerprint\Matching\MatcherSettings;
use NutriCompare\Fingerprint\Support\Config;

/**
 * The omission gate's settings ({@see ProbeOmission}), normalised: whether it may raise a
 * verdict to `challenge`, the minimum share (percent, 1..100) of the expected probes that must
 * be reported, and the purposes it applies to — filtered to the host's collection purposes, so
 * a typo cannot name a purpose that never occurs.
 *
 * Moved here from the application's settings store in the one-engine migration (2026-10-21)
 * for the reason {@see MatcherSettings} was: the
 * application's store calls this same function with its stored values, so a plain-PHP host
 * and the application agree on the defaults and the clamps. Normalising an already-normalised
 * array returns it unchanged (pinned by a unit test).
 *
 * @phpstan-type Normalised array{enabled: bool, min_reported: int, purposes: list<string>}
 */
final class OmissionGateSettings
{
    /** Gate on unless a host switched it off. */
    public const DEFAULT_ENABLED = true;

    /** The minimum reported share, in percent, below which an envelope fires the gate. */
    public const DEFAULT_MIN_REPORTED = 85;

    /**
     * The settings the engine runs with: `fingerprint.omission_gate` from {@see Config},
     * filtered against `fingerprint.purposes`.
     *
     * @return Normalised
     */
    public static function current(): array
    {
        return self::fromConfig(Config::array('fingerprint.omission_gate'), Config::array('fingerprint.purposes'));
    }

    /**
     * @param  array<array-key, mixed>  $configured  `enabled` (bool), `min_reported` (number),
     *                                               `purposes` (list of purpose names)
     * @param  array<array-key, mixed>  $knownPurposes  the purposes the host collects for
     * @return Normalised
     */
    public static function fromConfig(array $configured, array $knownPurposes): array
    {
        $known = [];
        foreach ($knownPurposes as $purpose) {
            if (is_string($purpose) && $purpose !== '') {
                $known[] = $purpose;
            }
        }

        $purposes = [];
        foreach (is_array($configured['purposes'] ?? null) ? $configured['purposes'] : [] as $purpose) {
            if (is_string($purpose) && in_array($purpose, $known, true) && ! in_array($purpose, $purposes, true)) {
                $purposes[] = $purpose;
            }
        }

        $enabled = $configured['enabled'] ?? null;
        $minimum = $configured['min_reported'] ?? null;

        return [
            'enabled' => is_bool($enabled) ? $enabled : self::DEFAULT_ENABLED,
            'min_reported' => max(1, min(100, is_numeric($minimum) ? (int) $minimum : self::DEFAULT_MIN_REPORTED)),
            'purposes' => $purposes,
        ];
    }
}

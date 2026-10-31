<?php

declare(strict_types=1);

namespace DeviceId\Signals;

use DeviceId\Detectors\ReviewItem;
use DeviceId\Model\FeatureCatalogue;

/**
 * Velocity and impossible travel as PURE FUNCTIONS over history the host supplies. The package
 * stores nothing and runs no query: the host selects the recent events of a device key, a
 * network or an account from its own tables and calls these. Nothing here blocks or scores a
 * visitor; the results are account flags, review items and model features.
 *
 * ## Bursts
 *
 * {@see burst()} counts the events of ONE subject inside a sliding window ending at `$now` and
 * reports when the count reaches the configured limit. Events after `$now` and older than the
 * window are ignored, so a re-run later gives the same answer for the same history.
 *
 * ## Impossible travel, and why it is conservative on purpose
 *
 * The geo dataset knows a COUNTRY, not a position. {@see impossibleTravel()} therefore uses the
 * smallest possible distance between the two countries (a lower bound taken between their
 * bounding boxes, {@see CountryBounds}; adjacent or overlapping countries are 0 km apart) and the
 * observed time between the two sessions. If even that minimum needs more than `maxSpeedKmh`, the
 * pair is impossible. It will miss a lot (Paris to Cayenne is one box), and it cannot be fooled
 * into a false alarm by a large country's centroid. Honest causes it can still report: a VPN or
 * proxy exit (hence the `anonymised` flag, which suppresses the pair), a shared account, a
 * mobile network that geolocates wrongly, and two devices of one household travelling apart.
 */
final class Velocity
{
    private const EARTH_RADIUS_KM = 6371.0088;

    /** Distinct device keys one ACCOUNT was used from. */
    public const DEVICES_PER_ACCOUNT = 'devices_per_account';

    /** Distinct accounts one DEVICE KEY was used for. */
    public const ACCOUNTS_PER_DEVICE = 'accounts_per_device';

    /** Distinct e-mail addresses (hashes) used from one NETWORK. */
    public const EMAILS_PER_NETWORK = 'emails_per_network';

    private const DISTINCT_SUBJECTS = [
        self::DEVICES_PER_ACCOUNT => 'account',
        self::ACCOUNTS_PER_DEVICE => 'device_key',
        self::EMAILS_PER_NETWORK => 'network_hash',
    ];

    /**
     * @param  string  $event  `signup` or `login`
     * @param  string  $subjectKind  `device_key`, `network_hash` or `account`
     * @param  list<int>  $timestamps  unix times of the subject's events
     */
    public static function burst(string $event, string $subjectKind, string $subject, array $timestamps, int $now, ?VelocityThresholds $thresholds = null): ?VelocityFinding
    {
        $thresholds ??= VelocityThresholds::fromConfig();
        $network = $subjectKind === 'network_hash';
        $limit = match ($event) {
            'signup' => $network ? $thresholds->signupsPerNetwork : $thresholds->signupsPerDevice,
            'login' => $network ? $thresholds->loginsPerNetwork : $thresholds->loginsPerDevice,
            default => throw new \InvalidArgumentException("unknown event kind '{$event}'"),
        };

        $count = self::countInWindow($timestamps, $now, $thresholds->windowSeconds);
        if ($count < $limit) {
            return null;
        }

        // A network is shared by design, so it is informational at the limit and medium at double.
        $severity = match (true) {
            $count >= 2 * $limit && ! $network => ReviewItem::SEVERITY_HIGH,
            $count >= 2 * $limit => ReviewItem::SEVERITY_MEDIUM,
            $network => ReviewItem::SEVERITY_INFORMATIONAL,
            default => ReviewItem::SEVERITY_MEDIUM,
        };

        return new VelocityFinding(VelocityFinding::BURST, $subjectKind, $subject, $severity, [
            'event' => $event, 'count' => $count, 'limit' => $limit, 'window_seconds' => $thresholds->windowSeconds,
        ]);
    }

    /**
     * Velocity v2: how many DISTINCT values one subject touched in each of three windows (1 hour,
     * 24 hours, 7 days), for one relation:
     *
     * - {@see ACCOUNTS_PER_DEVICE}: `$subject` is a device key, each event's `value` an account id
     * - {@see DEVICES_PER_ACCOUNT}: `$subject` is an account, `value` a device key
     * - {@see EMAILS_PER_NETWORK}: `$subject` is a network hash, `value` a keyed hash of the e-mail address
     *
     * Returns one finding per window whose distinct count reaches the limit
     * ({@see VelocityThresholds::$distinct}), so a short burst and a slow drip are both reported
     * and each is its own model feature. The same value twice counts once; events after `$now` and
     * older than the window are ignored, so a re-run gives the same answer. Accounts-per-device
     * stays silent when the count reaches the k-floor: a key shared by that many accounts is a
     * device class, not a ring. A network is shared by design, so its findings are informational
     * at the limit and medium at double.
     *
     * @param  string  $relation  one of the three relation constants
     * @param  list<array{at: int, value: string}>  $events  the subject's events, any order
     * @return list<VelocityFinding>
     */
    public static function distinct(string $relation, string $subject, array $events, int $now, ?VelocityThresholds $thresholds = null): array
    {
        $kind = self::DISTINCT_SUBJECTS[$relation] ?? throw new \InvalidArgumentException("unknown velocity relation '{$relation}'");
        $thresholds ??= VelocityThresholds::fromConfig();

        $findings = [];
        foreach (VelocityThresholds::WINDOWS as $label => $seconds) {
            $values = [];
            foreach ($events as $event) {
                if (is_array($event) && is_int($event['at'] ?? null) && is_string($event['value'] ?? null) && $event['at'] > $now - $seconds && $event['at'] <= $now) {
                    $values[$event['value']] = true;
                }
            }
            $count = count($values);
            $limit = $thresholds->distinct[$relation][$label];
            if ($count < $limit || ($relation === self::ACCOUNTS_PER_DEVICE && $count >= $thresholds->distinctKFloor)) {
                continue;
            }

            $severity = match (true) {
                $kind === 'network_hash' && $count >= 2 * $limit => ReviewItem::SEVERITY_MEDIUM,
                $kind === 'network_hash' => ReviewItem::SEVERITY_INFORMATIONAL,
                $count >= 2 * $limit => ReviewItem::SEVERITY_HIGH,
                default => ReviewItem::SEVERITY_MEDIUM,
            };
            $findings[] = new VelocityFinding(VelocityFinding::DISTINCT, $kind, $subject, $severity, [
                'relation' => $relation, 'window' => $label, 'distinct' => $count, 'limit' => $limit, 'window_seconds' => $seconds,
            ]);
        }

        return $findings;
    }

    /**
     * @param  list<int>  $timestamps
     */
    public static function countInWindow(array $timestamps, int $now, int $windowSeconds): int
    {
        $from = $now - $windowSeconds;

        return count(array_filter($timestamps, static fn (mixed $t): bool => is_int($t) && $t > $from && $t <= $now));
    }

    /**
     * The worst impossible pair among an account's consecutive sessions, or null.
     *
     * @param  list<array{at: int, country: string|null, anonymised?: bool}>  $sessions  any order; `anonymised`
     *                                                                                   is true when the session came through a VPN, proxy, hosting or Tor address, whose country says
     *                                                                                   nothing about the person
     */
    public static function impossibleTravel(string $account, array $sessions, ?VelocityThresholds $thresholds = null): ?VelocityFinding
    {
        $thresholds ??= VelocityThresholds::fromConfig();

        $usable = [];
        foreach ($sessions as $session) {
            $country = is_string($session['country'] ?? null) ? strtoupper($session['country']) : null;
            if (is_int($session['at'] ?? null) && $country !== null && isset(CountryBounds::BOXES[$country])) {
                $usable[] = ['at' => $session['at'], 'country' => $country, 'anonymised' => ($session['anonymised'] ?? false) === true];
            }
        }
        usort($usable, static fn (array $a, array $b): int => $a['at'] <=> $b['at']);

        $worst = null;
        for ($i = 1; $i < count($usable); $i++) {
            [$from, $to] = [$usable[$i - 1], $usable[$i]];
            if ($from['anonymised'] || $to['anonymised'] || $from['country'] === $to['country']) {
                continue;
            }

            $distance = self::minimumDistanceKm($from['country'], $to['country']);
            if ($distance === null || $distance < $thresholds->minDistanceKm) {
                continue;
            }

            $hours = max($thresholds->minSecondsBetween, $to['at'] - $from['at']) / 3600.0;
            $speed = $distance / $hours;
            if ($speed > $thresholds->maxSpeedKmh && ($worst === null || $speed > $worst['speed'])) {
                $worst = ['speed' => $speed, 'distance' => $distance, 'seconds' => $to['at'] - $from['at'], 'from' => $from['country'], 'to' => $to['country']];
            }
        }

        if ($worst === null) {
            return null;
        }

        return new VelocityFinding(VelocityFinding::IMPOSSIBLE_TRAVEL, 'account', $account,
            $worst['speed'] > 3 * $thresholds->maxSpeedKmh ? ReviewItem::SEVERITY_HIGH : ReviewItem::SEVERITY_MEDIUM, [
                'from_country' => $worst['from'], 'to_country' => $worst['to'],
                'min_distance_km' => (int) round($worst['distance']), 'seconds' => $worst['seconds'],
                'min_speed_kmh' => (int) round($worst['speed']), 'max_speed_kmh' => $thresholds->maxSpeedKmh,
            ]);
    }

    /**
     * A lower bound of the distance in km between two countries: the great-circle distance
     * between their bounding boxes (0 when they touch or overlap). Null for an unknown code.
     */
    public static function minimumDistanceKm(string $countryA, string $countryB): ?float
    {
        $a = CountryBounds::BOXES[strtoupper($countryA)] ?? null;
        $b = CountryBounds::BOXES[strtoupper($countryB)] ?? null;
        if ($a === null || $b === null) {
            return null;
        }

        $latGap = max(0.0, $a[0] - $b[2], $b[0] - $a[2]);
        // Longitude gap the short way round: the smaller of the direct gap and the one across the antimeridian.
        $direct = max(0.0, $a[1] - $b[3], $b[1] - $a[3]);
        $across = max(0.0, 360.0 - (max($a[3], $b[3]) - min($a[1], $b[1])));
        $lonGap = min($direct, $across);
        if ($latGap === 0.0 && $lonGap === 0.0) {
            return 0.0;
        }

        // cos(L) with L the largest absolute latitude of either box: the smallest cosine, so the
        // longitude term can only under-estimate. The haversine is monotone in both terms.
        $limit = max(abs($a[0]), abs($a[2]), abs($b[0]), abs($b[2]));
        $cos = cos(deg2rad(min(89.0, $limit)));
        $h = sin(deg2rad($latGap) / 2) ** 2 + $cos * $cos * sin(deg2rad($lonGap) / 2) ** 2;

        return 2 * self::EARTH_RADIUS_KM * asin(min(1.0, sqrt($h)));
    }

    /**
     * Model features of a visit: `vel_burst` when any burst finding exists for it,
     * `vel_impossible_travel` when the account has one, and `vel_<relation>_<window>` for each
     * distinct-count finding ({@see distinct()}). Only those that hold.
     *
     * @param  list<VelocityFinding>  $findings
     * @return array<string, float>
     *
     * @see FeatureCatalogue::VELOCITY
     */
    public static function features(array $findings): array
    {
        $features = [];
        foreach ($findings as $finding) {
            if ($finding->code === VelocityFinding::BURST) {
                $features['vel_burst'] = 1.0;
            } elseif ($finding->code === VelocityFinding::IMPOSSIBLE_TRAVEL) {
                $features['vel_impossible_travel'] = 1.0;
            } elseif ($finding->code === VelocityFinding::DISTINCT) {
                $features['vel_'.$finding->evidence['relation'].'_'.$finding->evidence['window']] = 1.0;
            }
        }

        return $features;
    }
}

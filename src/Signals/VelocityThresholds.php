<?php

declare(strict_types=1);

namespace DeviceId\Signals;

use DeviceId\Support\Config;

/**
 * The thresholds of {@see Velocity}. Every number is a starting point a host tunes from its own
 * confirm/dismiss ratio, and each is read from configuration (`fingerprint.velocity.*`) by
 * {@see fromConfig()}: nothing in the functions is hardcoded.
 *
 * - `windowSeconds`: the sliding window events are counted in (default one hour).
 * - `signupsPerDevice`, `loginsPerDevice`: events from ONE device key inside the window that make a
 *   burst. A person signs up once and signs in a handful of times; a device key is shared by a
 *   device class, so hosts apply the k-floor of the ring detectors before acting on it.
 * - `signupsPerNetwork`, `loginsPerNetwork`: higher, because a campus, an office or a carrier NAT
 *   puts many honest people behind one address.
 * - `maxSpeedKmh`: the speed above which two sessions of one account cannot be one traveller. 1000
 *   is above an airliner's cruise (about 900) so that only the impossible is reported.
 * - `minDistanceKm`: a pair closer than this (a lower bound of the distance between the two
 *   countries' bounding boxes) is never judged: geolocation errors, border towns and roaming
 *   dwarf it.
 * - `minSecondsBetween`: the time between two sessions is never taken below this, so two requests
 *   one second apart on a mobile network that changed country mid-handover do not produce an
 *   absurd speed.
 * - `distinct`: velocity v2. For each relation ({@see Velocity::ACCOUNTS_PER_DEVICE},
 *   {@see Velocity::DEVICES_PER_ACCOUNT}, {@see Velocity::EMAILS_PER_NETWORK}) the number of
 *   DISTINCT values in each window ({@see WINDOWS}: `1h`, `24h`, `7d`) that makes a finding. A
 *   household shares a device between two or three people; a campus puts many addresses behind one
 *   network, hence the larger network limits. Limits never decrease with the window.
 * - `distinctKFloor`: a device key shared by this many accounts or more is a device class (every
 *   phone of a model with the same key), not a ring, and accounts-per-device stays silent
 *   (the owner's k-floor of 20).
 */
final readonly class VelocityThresholds
{
    /** @var array<string, int> window label => seconds */
    public const WINDOWS = ['1h' => 3600, '24h' => 86400, '7d' => 604800];

    /** @var array<string, array<string, int>> */
    public const DEFAULT_DISTINCT = [
        'accounts_per_device' => ['1h' => 3, '24h' => 4, '7d' => 6],
        'devices_per_account' => ['1h' => 3, '24h' => 5, '7d' => 8],
        'emails_per_network' => ['1h' => 6, '24h' => 12, '7d' => 25],
    ];

    /**
     * @param  array<string, array<string, int>>  $distinct  relation => window label => distinct count that makes a finding
     */
    public function __construct(
        public int $windowSeconds = 3600,
        public int $signupsPerDevice = 3,
        public int $loginsPerDevice = 10,
        public int $signupsPerNetwork = 8,
        public int $loginsPerNetwork = 30,
        public float $maxSpeedKmh = 1000.0,
        public float $minDistanceKm = 500.0,
        public int $minSecondsBetween = 300,
        public array $distinct = self::DEFAULT_DISTINCT,
        public int $distinctKFloor = 20,
    ) {
        foreach (self::DEFAULT_DISTINCT as $relation => $windows) {
            $previous = 2;
            foreach (array_keys($windows) as $window) {
                $limit = $distinct[$relation][$window] ?? null;
                if (! is_int($limit) || $limit < $previous) {
                    throw new \InvalidArgumentException("velocity distinct limit {$relation}.{$window} out of range");
                }
                $previous = $limit;
            }
        }
        if ($distinctKFloor < 2) {
            throw new \InvalidArgumentException('velocity distinct k-floor out of range');
        }
        if ($windowSeconds < 1 || $signupsPerDevice < 2 || $loginsPerDevice < 2 || $signupsPerNetwork < 2 || $loginsPerNetwork < 2
            || $maxSpeedKmh <= 0.0 || $minDistanceKm < 0.0 || $minSecondsBetween < 1) {
            throw new \InvalidArgumentException('velocity thresholds out of range');
        }
    }

    public static function fromConfig(): self
    {
        $defaults = new self;

        return new self(
            max(1, Config::int('fingerprint.velocity.window_seconds', $defaults->windowSeconds)),
            max(2, Config::int('fingerprint.velocity.signups_per_device', $defaults->signupsPerDevice)),
            max(2, Config::int('fingerprint.velocity.logins_per_device', $defaults->loginsPerDevice)),
            max(2, Config::int('fingerprint.velocity.signups_per_network', $defaults->signupsPerNetwork)),
            max(2, Config::int('fingerprint.velocity.logins_per_network', $defaults->loginsPerNetwork)),
            max(1.0, Config::float('fingerprint.velocity.max_speed_kmh', $defaults->maxSpeedKmh)),
            max(0.0, Config::float('fingerprint.velocity.min_distance_km', $defaults->minDistanceKm)),
            max(1, Config::int('fingerprint.velocity.min_seconds_between', $defaults->minSecondsBetween)),
            self::distinctFromConfig(),
            max(2, Config::int('fingerprint.velocity.distinct_k_floor', $defaults->distinctKFloor)),
        );
    }

    /**
     * `fingerprint.velocity.distinct.<relation>.<window>`; a limit below the previous window's is
     * raised to it (a typo must not throw on the request path).
     *
     * @return array<string, array<string, int>>
     */
    private static function distinctFromConfig(): array
    {
        $out = [];
        foreach (self::DEFAULT_DISTINCT as $relation => $windows) {
            $previous = 2;
            foreach ($windows as $window => $default) {
                $limit = max($previous, Config::int("fingerprint.velocity.distinct.{$relation}.{$window}", $default));
                $out[$relation][$window] = $limit;
                $previous = $limit;
            }
        }

        return $out;
    }
}

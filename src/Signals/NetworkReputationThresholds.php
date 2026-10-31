<?php

declare(strict_types=1);

namespace DeviceId\Signals;

use DeviceId\Support\Config;

/**
 * The thresholds of {@see NetworkReputation}, read from `fingerprint.network_reputation.*`.
 *
 * - `kFloor`: fewer distinct devices than this and the network is not judged (default 20, the
 *   owner's k-floor).
 * - `minimumBad`: the weighted number of labelled devices below which the share is noise.
 * - `badShare`: the weighted share of the network's devices that makes it `bad`.
 */
final readonly class NetworkReputationThresholds
{
    public function __construct(
        public int $kFloor = 20,
        public float $minimumBad = 5.0,
        public float $badShare = 0.3,
    ) {
        if ($kFloor < 2 || $minimumBad <= 0.0 || $badShare <= 0.0 || $badShare > 1.0) {
            throw new \InvalidArgumentException('network reputation thresholds out of range');
        }
    }

    public static function fromConfig(): self
    {
        $defaults = new self;

        return new self(
            max(2, Config::int('fingerprint.network_reputation.k_floor', $defaults->kFloor)),
            max(0.5, Config::float('fingerprint.network_reputation.minimum_bad', $defaults->minimumBad)),
            min(1.0, max(0.01, Config::float('fingerprint.network_reputation.bad_share', $defaults->badShare))),
        );
    }
}

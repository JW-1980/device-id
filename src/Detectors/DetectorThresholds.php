<?php

declare(strict_types=1);

namespace DeviceId\Detectors;

/**
 * The thresholds of the population detectors. The defaults are the owner's decisions (k-floor
 * 20); the rest are starting points a host tunes from its own confirm/dismiss ratio, which is
 * the number that says whether a detector is any good (see {@see RingDetectors}).
 */
final readonly class DetectorThresholds
{
    public function __construct(
        /** A cohort or baseline smaller than this is not judged and not reported with counts. */
        public int $kFloor = 20,
        /** Distinct accounts seen on one device key inside the window before it is queued. */
        public int $accountsPerDevice = 4,
        /** Distinct devices seen on one account inside the window before it is queued. */
        public int $devicesPerAccount = 6,
        /** Observations from one network inside the window before a burst is considered. */
        public int $burstMinimumCount = 15,
        /** How many times the baseline mean the window must reach. */
        public float $burstRatio = 5.0,
    ) {
        if ($kFloor < 1 || $accountsPerDevice < 2 || $devicesPerAccount < 2 || $burstMinimumCount < 1 || $burstRatio <= 1.0) {
            throw new \InvalidArgumentException('detector thresholds out of range');
        }
    }
}

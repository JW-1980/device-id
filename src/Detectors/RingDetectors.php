<?php

declare(strict_types=1);

namespace DeviceId\Detectors;

/**
 * Population and ring detectors as PURE FUNCTIONS over aggregates the host computes.
 *
 * The package has no storage and runs no SQL. A host runs one GROUP BY per detector over its own
 * tables, hands the rows in, and receives {@see ReviewItem}s for its review queue. Nothing here
 * blocks, challenges or scores a visitor: a detector's output is a person's to-do list, and the
 * number that grades a detector is its confirm/dismiss ratio in that queue (a dismissed share
 * above the owner's bound, 50 % proposed, retires or retunes it).
 *
 * ## The k-floor (20), and the two things it does
 *
 * 1. A burst is judged against a baseline, and a baseline built from fewer than `kFloor`
 *    observations is noise: the network is not judged (it is returned in `unjudged` counts).
 * 2. A device key shared by `kFloor` or more accounts is a device CLASS (every phone of one
 *    model on one OS release shares a key), not a person: it is reported as informational with
 *    the recommendation to treat the key as non-identifying, and its accounts are NOT queued.
 *    Queuing 25 strangers because they own the same phone is the false positive this guards.
 *
 * ## Expected host SQL (one row per subject, inside the host's window)
 *
 * - accounts per device key: `device_key, COUNT(DISTINCT account) AS accounts, COUNT(DISTINCT network_hash) AS networks`
 * - devices per account:     `account, COUNT(DISTINCT device_key) AS devices, COUNT(DISTINCT network_hash) AS networks`
 * - bursts per network:      `network_hash, count (window), baseline_mean (per window, trailing), baseline_n (observations in the baseline)`
 */
final class RingDetectors
{
    /**
     * @param  iterable<array{device_key: string, accounts: int, networks?: int}>  $rows
     * @return list<ReviewItem>
     */
    public static function accountsPerDevice(iterable $rows, DetectorThresholds $thresholds = new DetectorThresholds): array
    {
        $items = [];
        foreach ($rows as $row) {
            $accounts = (int) $row['accounts'];
            $networks = (int) ($row['networks'] ?? 0);

            if ($accounts >= $thresholds->kFloor) {
                $items[] = new ReviewItem('device_key_is_a_class', 'device_key', (string) $row['device_key'], ReviewItem::SEVERITY_INFORMATIONAL,
                    ['accounts' => '>='.$thresholds->kFloor, 'k_floor' => $thresholds->kFloor],
                    'Treat this key as a device class, not a person: do not queue its accounts. Consider excluding it from account-sharing rules.');

                continue;
            }
            if ($accounts < $thresholds->accountsPerDevice) {
                continue;
            }

            $items[] = new ReviewItem('accounts_per_device', 'device_key', (string) $row['device_key'],
                $accounts >= 2 * $thresholds->accountsPerDevice || $networks >= 3 ? ReviewItem::SEVERITY_HIGH : ReviewItem::SEVERITY_MEDIUM,
                ['accounts' => $accounts, 'networks' => $networks, 'threshold' => $thresholds->accountsPerDevice],
                'Review the accounts as a group (same household and shared devices are common). Confirm only with a second signal such as shared payment or contact details.');
        }

        return self::sorted($items);
    }

    /**
     * @param  iterable<array{account: string, devices: int, networks?: int}>  $rows
     * @return list<ReviewItem>
     */
    public static function devicesPerAccount(iterable $rows, DetectorThresholds $thresholds = new DetectorThresholds): array
    {
        $items = [];
        foreach ($rows as $row) {
            $devices = (int) $row['devices'];
            $networks = (int) ($row['networks'] ?? 0);
            if ($devices < $thresholds->devicesPerAccount) {
                continue;
            }

            $items[] = new ReviewItem('devices_per_account', 'account', (string) $row['account'],
                $devices >= 2 * $thresholds->devicesPerAccount || $networks >= 4 ? ReviewItem::SEVERITY_HIGH : ReviewItem::SEVERITY_MEDIUM,
                ['devices' => $devices, 'networks' => $networks, 'threshold' => $thresholds->devicesPerAccount],
                'Possible credential sharing or takeover. Check recent sign-in changes before any action; one person owns many devices and clears cookies more often than expected.');
        }

        return self::sorted($items);
    }

    /**
     * @param  iterable<array{network_hash: string, count: int, baseline_mean: float|int, baseline_n: int}>  $rows
     * @return array{items: list<ReviewItem>, unjudged: int} `unjudged`: networks whose baseline was below the k-floor
     */
    public static function networkBursts(iterable $rows, DetectorThresholds $thresholds = new DetectorThresholds): array
    {
        $items = [];
        $unjudged = 0;
        foreach ($rows as $row) {
            $count = (int) $row['count'];
            if ($count < $thresholds->burstMinimumCount) {
                continue;
            }
            if ((int) $row['baseline_n'] < $thresholds->kFloor) {
                $unjudged++;

                continue;
            }
            $mean = max(0.0, (float) $row['baseline_mean']);
            $ratio = $count / max(1.0, $mean);
            if ($ratio < $thresholds->burstRatio) {
                continue;
            }

            $items[] = new ReviewItem('network_burst', 'network_hash', (string) $row['network_hash'],
                $ratio >= 2 * $thresholds->burstRatio ? ReviewItem::SEVERITY_HIGH : ReviewItem::SEVERITY_MEDIUM,
                ['count' => $count, 'baseline_mean' => round($mean, 2), 'ratio' => round($ratio, 1), 'baseline_n' => (int) $row['baseline_n']],
                'A shared network (campus, carrier NAT, office) bursts for innocent reasons. Look at how many distinct device keys and accounts are inside the burst before acting.');
        }

        return ['items' => self::sorted($items), 'unjudged' => $unjudged];
    }

    /**
     * Every detector over one set of aggregates, sorted most severe first.
     *
     * @param  array{accounts_per_device?: iterable<array<string, mixed>>, devices_per_account?: iterable<array<string, mixed>>, network_bursts?: iterable<array<string, mixed>>}  $aggregates
     * @return list<ReviewItem>
     */
    public static function all(array $aggregates, DetectorThresholds $thresholds = new DetectorThresholds): array
    {
        return self::sorted([
            ...self::accountsPerDevice($aggregates['accounts_per_device'] ?? [], $thresholds),
            ...self::devicesPerAccount($aggregates['devices_per_account'] ?? [], $thresholds),
            ...self::networkBursts($aggregates['network_bursts'] ?? [], $thresholds)['items'],
        ]);
    }

    /**
     * Sends items to the host's queue.
     *
     * @param  list<ReviewItem>  $items
     */
    public static function enqueueAll(array $items, ReviewSink $sink): int
    {
        foreach ($items as $item) {
            $sink->enqueue($item);
        }

        return count($items);
    }

    /**
     * @param  list<ReviewItem>  $items
     * @return list<ReviewItem>
     */
    private static function sorted(array $items): array
    {
        $rank = [ReviewItem::SEVERITY_HIGH => 0, ReviewItem::SEVERITY_MEDIUM => 1, ReviewItem::SEVERITY_INFORMATIONAL => 2];
        usort($items, static fn (ReviewItem $a, ReviewItem $b): int => $rank[$a->severity] <=> $rank[$b->severity] ?: strcmp($a->detector.$a->subject, $b->detector.$b->subject));

        return $items;
    }
}

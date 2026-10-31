<?php

declare(strict_types=1);

namespace DeviceId\Matching;

/**
 * The state of a device row's link, decided when the link is written and stored in
 * `link_state` (round-3 R3-S7): consumers read the decision, never re-derive it from the
 * stored posterior against the CURRENT `link_posterior` threshold, so lowering that
 * setting cannot turn yesterday's provisional or possible rows into real links.
 *
 * - `final`: a real link — the row joined the target's cluster (`cluster_id` set). Since
 *   round 3 (R3-S2) only from the target's own network (`MatchCandidate::matchNetwork()`).
 * - `provisional`: the row matched a device from ANOTHER network. Recorded with
 *   `linked_device_id`, `link_method` and a posterior below the threshold, no cluster; it
 *   becomes final only when a later report of this row arrives from the target's network.
 *   A "possibly the same device across networks" signal for administrators only: it
 *   feeds no risk rule and no enforcement (round-3b R3b-1).
 * - `possible`: a weaker candidate (`link_method = possible`), recorded for review only.
 */
final class LinkState
{
    public const FINAL = 'final';

    public const PROVISIONAL = 'provisional';

    public const POSSIBLE = 'possible';

    /** @var list<string> */
    public const ALL = [self::FINAL, self::PROVISIONAL, self::POSSIBLE];

    /**
     * The state a link written without an explicit state is given, at write time: the
     * decision is taken once, against the threshold in force when the row is saved.
     */
    public static function derive(?int $target, ?string $method, ?float $posterior, float $threshold): ?string
    {
        if ($target === null || $method === null) {
            return null;
        }

        if ($method === self::POSSIBLE) {
            return self::POSSIBLE;
        }

        return ($posterior ?? 0.0) >= $threshold ? self::FINAL : self::PROVISIONAL;
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Matching;

/**
 * A stored device row as `DeviceMatcher` scores it: its id, its cluster root, the
 * quantised component map and the two keys. `FingerprintDevice` (the claim-phase store)
 * and `VisitorDevice` (the `nc_vid` identity store) both implement it through the
 * {@see MatchesAsCandidate} trait, so one matcher serves both tables and the scoring
 * arithmetic exists once.
 */
interface MatchCandidate
{
    public function matchId(): int;

    /**
     * The root of the link chain this row belongs to (`cluster_id`, or the row itself
     * when it is unlinked). A link made to any member of a cluster is recorded against
     * the root, so clusters never nest (round-2 decision G-D1i).
     */
    public function matchClusterId(): int;

    /**
     * The stored `DeviceComponents` map; empty when the row has none.
     *
     * @return array<string, scalar|null>
     */
    public function matchComponents(): array;

    public function matchBrowserKey(): ?string;

    /**
     * The row's same-network token, or null: a match is FINAL only when the report's token
     * equals it (round-3 R3-S2). Both stores use the keyed IPv4 /24 or IPv6 /56 code
     * (`link_network`, round-3b R3b-4; the application's `LinkNetwork`) — neither stores a prefix in
     * the clear — and the caller passes the request's token of the same kind.
     * Null never equals anything.
     */
    public function matchNetwork(): ?string;

    public function matchHardwareKey(): ?string;
}

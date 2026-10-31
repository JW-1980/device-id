<?php

declare(strict_types=1);

namespace DeviceId\Matching;

/**
 * Where `DeviceMatcher` reads candidate rows from.
 *
 * The matcher owns the decision (exact browser key, then scored hardware candidates,
 * then the link/possible/new thresholds); a source owns only the two queries, so the
 * same scoring serves `fingerprint_devices` (FingerprintDeviceCandidates) and
 * `visitor_devices` (VisitorDeviceCandidates) without a second copy of the maths.
 *
 * Both stages read the `device_browser_keys` link table as well as the row's own key
 * column (round-2 decision G-D3i): a device's second browser is recorded against the
 * cluster root when a hardware link is made, so its next visit is an EXACT match.
 */
interface DeviceCandidateSource
{
    /**
     * The one device whose stored browser key — own column or link table — equals
     * `$browserKey`, or null when there is none, or when the source cannot name exactly
     * one cluster (several unrelated rows share the key, which a non-unique store may
     * hold; the scored stage then sees them all).
     *
     * @param  int  $windowDays  only rows seen this recently, where the store is not unique on the key
     * @param  string|null  $ipPrefix  the request's network: among several rows carrying the key the
     *                                 one seen from this network is preferred (a browser on its own
     *                                 network is final there, round-2 FR2-1 residual)
     */
    public function exact(string $browserKey, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, ?string $ipPrefix = null): ?MatchCandidate;

    /**
     * Rows seen inside the window whose `hardware_key` equals `$hardwareKey`, then rows
     * whose `block_tuple` equals `$blockTuple`, newest first, at most `$maxCandidates` in
     * all — two index-backed lookups, never a JSON-path scan (round-2 BE2-03 / PERF-17).
     * At least one of the two blocking keys is non-null.
     *
     * @return list<MatchCandidate>
     */
    public function candidates(?string $hardwareKey, ?string $blockTuple, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, int $maxCandidates): array;

    /**
     * Record `$browserKey` as a second key of the cluster rooted at `$deviceId` (G-D3i), so
     * the same browser is an exact match on its next visit. Idempotent.
     */
    public function addBrowserKey(int $deviceId, string $browserKey, int $saltVersion): void;
}

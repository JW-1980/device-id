<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Crawlers;

use NutriCompare\Fingerprint\Support\Verdict;

/**
 * Classifies a request before any fingerprint or bot scoring runs.
 *
 * Order, strongest first:
 *  1. the operator allowlist (IP/CIDR, device key)      -> `ALLOW_LISTED`
 *  2. a crawler whose identity is verified               -> `ALLOW_VERIFIED_CRAWLER`
 *  3. an enabled uptime monitor whose provider's published IP list contains the address
 *                                                        -> `ALLOW_VERIFIED_MONITOR`
 *  4. anything else                                      -> `SCORE`
 *
 * It reads caches only (no DNS, no HTTP), so it is safe on the request path. Resolve cold claims
 * and refresh monitor lists in the background (`CrawlerVerifier::verifyAndCache()`,
 * `refreshMonitorLists()`).
 *
 * ## Monitors
 *
 * Only monitors the host ENABLES are consulted, and only their published IP lists decide (the
 * address alone is enough; the User-Agent is never). A User-Agent that names a monitor from an
 * address not on its list is NOT an impersonation signal: monitors change addresses and lists lag.
 * It is reported in `unlistedMonitorClaim` for logging and nothing else. With no list available
 * the answer is "not listed" (fail closed).
 */
final class TrafficGate
{
    /**
     * @param  list<string>  $enabledMonitors  catalogue keys; empty means none
     */
    public function __construct(
        private readonly CrawlerVerifier $verifier,
        private readonly OperatorAllowlist $allowlist,
        private readonly ?IpRangeDirectory $ranges = null,
        private readonly array $enabledMonitors = [],
        private readonly ?CrawlerCatalogue $catalogue = null,
    ) {}

    public function classify(string $ip, ?string $userAgent, ?string $deviceKey = null): TrafficClassification
    {
        $verification = $this->safeLookup($ip, $userAgent);

        $entry = $this->allowlist->matchIp($ip);
        if ($entry !== null) {
            return new TrafficClassification(Verdict::ALLOW_LISTED, $verification, 'ip', $entry);
        }

        if ($this->allowlist->matchesDeviceKey($deviceKey)) {
            return new TrafficClassification(Verdict::ALLOW_LISTED, $verification, 'device_key');
        }

        if ($verification->isVerified()) {
            return new TrafficClassification(Verdict::ALLOW_VERIFIED_CRAWLER, $verification, null, $verification->crawler);
        }

        foreach ($this->enabledMonitors as $monitor) {
            if ($this->ranges !== null && $this->safeContains($monitor, $ip)) {
                return new TrafficClassification(Verdict::ALLOW_VERIFIED_MONITOR, $verification, null, $monitor);
            }
        }

        $claim = $this->catalogue?->monitorClaimFor($userAgent);

        return new TrafficClassification(
            Verdict::DECISION_SCORE,
            $verification,
            null,
            null,
            $claim !== null && in_array($claim, $this->enabledMonitors, true) ? $claim : null,
        );
    }

    /**
     * Refresh the enabled monitors' lists that are stale or missing (a blocking fetch: call after
     * the response or from a scheduler). A failed fetch keeps the last good list.
     *
     * @return array<string, bool> monitor => a usable list is available
     */
    public function refreshMonitorLists(): array
    {
        $result = [];
        foreach ($this->enabledMonitors as $monitor) {
            $result[$monitor] = $this->ranges?->refreshIfStale($monitor) ?? false;
        }

        return $result;
    }

    /**
     * @return list<string>
     */
    public function monitorsNeedingRefresh(): array
    {
        if ($this->ranges === null) {
            return [];
        }

        return array_values(array_filter($this->enabledMonitors, fn (string $m): bool => $this->ranges->isStale($m)));
    }

    /**
     * @return list<string>
     */
    public function enabledMonitors(): array
    {
        return $this->enabledMonitors;
    }

    private function safeLookup(string $ip, ?string $userAgent): CrawlerVerification
    {
        try {
            return $this->verifier->lookup($ip, $userAgent);
        } catch (\Throwable) {
            $claim = $this->verifier->claimFor($userAgent);

            return $claim === null ? CrawlerVerification::none() : CrawlerVerification::unverifiable($claim);
        }
    }

    private function safeContains(string $monitor, string $ip): bool
    {
        try {
            return $this->ranges?->contains($monitor, $ip, false) === true;
        } catch (\Throwable) {
            return false;
        }
    }
}

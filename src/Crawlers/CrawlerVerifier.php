<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Crawlers;

/**
 * Decides whether a "I am Googlebot" claim is true: reverse DNS, a check of the name against the
 * vendor's domain suffixes on a label boundary, then a forward lookup that must come back to the
 * same address. The forward confirmation is what makes it non-forgeable: an attacker who controls
 * the PTR record of their own address cannot make `crawl-x.googlebot.com` resolve to it. Vendors
 * that publish IP lists instead (or as well) are checked against those.
 *
 * ## Fail closed
 *
 * Every error path ends in `unverifiable`, never `verified`: no PTR answer, a DNS exception, an empty
 * forward set, a missing or unreadable list, a cache that is down. `forged` is reported only when
 * DNS (or a list that was actually read) CONTRADICTS the claim.
 *
 * ## Latency
 *
 * `lookup()` reads the cache and never touches DNS, so it is safe on the request path. A cold claim
 * is reported `pending`; the host resolves it in the background with `verifyAndCache()`, using
 * `claimResolution()` to dispatch once per address.
 *
 * Uptime monitors are not handled here: they are provable only by IP list and are decided by
 * `TrafficGate`.
 */
final class CrawlerVerifier
{
    private const CACHE_PREFIX = 'device-id:crawler:';

    private const PENDING_PREFIX = 'device-id:crawler-pending:';

    /**
     * @param  (\Closure(string): string)|null  $addressDigest  maps an address to the cache-key part;
     *                                                          default is sha256, hosts may key it so the
     *                                                          cache never holds the address
     */
    public function __construct(
        private readonly CrawlerCatalogue $catalogue,
        private readonly ?DnsResolver $dns = null,
        private readonly ?IpRangeDirectory $ranges = null,
        private readonly ?CrawlerCache $cache = null,
        private readonly int $ttl = 86400,
        private readonly int $undecidedTtl = 300,
        private readonly ?\Closure $addressDigest = null,
    ) {}

    public function claimFor(?string $userAgent): ?string
    {
        return $this->catalogue->crawlerClaimFor($userAgent);
    }

    /**
     * The state for this address and User-Agent from the cache alone. A miss is `pending`.
     */
    public function lookup(string $ip, ?string $userAgent): CrawlerVerification
    {
        $crawler = $this->claimFor($userAgent);
        if ($crawler === null) {
            return CrawlerVerification::none();
        }

        if ($ip === '' || IpAddress::pack($ip) === null || ! $this->canDecide($crawler)) {
            return CrawlerVerification::unverifiable($crawler);
        }

        return $this->cached($ip, $crawler) ?? CrawlerVerification::pending($crawler);
    }

    /**
     * Resolve now (blocking) and cache. Call from a queue worker or after the response; or inline in
     * a host that accepts the latency.
     */
    public function verifyAndCache(string $ip, string $crawler): CrawlerVerification
    {
        $verdict = $this->verify($ip, $crawler);

        // An undecided lookup is retried sooner: it is usually a transient resolver failure.
        $ttl = $verdict->status === CrawlerVerification::STATUS_UNVERIFIABLE ? $this->undecidedTtl : $this->ttl;

        try {
            if ($ttl > 0) {
                $this->cache?->put(self::CACHE_PREFIX.$this->keyPart($crawler, $ip), $verdict->toArray(), $ttl);
            }
            $this->cache?->forget(self::PENDING_PREFIX.$this->keyPart($crawler, $ip));
        } catch (\Throwable) {
        }

        return $verdict;
    }

    /**
     * True for exactly one caller per address per `undecidedTtl`: the one that should dispatch the
     * background resolution. A broken cache answers true (a duplicate job beats never verifying).
     */
    public function claimResolution(string $ip, string $crawler): bool
    {
        if ($this->cache === null || $this->undecidedTtl <= 0) {
            return true;
        }

        try {
            return $this->cache->add(self::PENDING_PREFIX.$this->keyPart($crawler, $ip), ['t' => time()], $this->undecidedTtl);
        } catch (\Throwable) {
            return true;
        }
    }

    /**
     * The decision itself: no caching, no queueing. Never throws.
     */
    public function verify(string $ip, string $crawler): CrawlerVerification
    {
        $definition = $this->catalogue->get($crawler);
        $packed = IpAddress::pack($ip);
        if ($definition === null || $definition->isMonitor() || $packed === null) {
            return CrawlerVerification::unverifiable($crawler);
        }

        // One spelling for every lookup: compressed IPv6, IPv4-mapped IPv6 folded to IPv4.
        $ip = (string) inet_ntop($packed);

        $byDns = $definition->rdnsSuffixes !== [] && $this->dns !== null
            ? $this->verifyByDns($ip, $crawler, $definition->rdnsSuffixes)
            : CrawlerVerification::unverifiable($crawler);

        if ($byDns->isVerified()) {
            return $byDns;
        }

        $inRange = null;
        if ($definition->hasRangeFeed() && $this->ranges !== null) {
            try {
                $inRange = $this->ranges->contains($crawler, $ip, true);
            } catch (\Throwable) {
                $inRange = null;
            }
        }

        if ($inRange === true) {
            return CrawlerVerification::verified($crawler, CrawlerVerification::RANGE_EVIDENCE);
        }

        if ($definition->rdnsSuffixes === []) {
            // The list is this vendor's only method: a list that was read and lacks the address
            // contradicts the claim; no list leaves it undecided.
            return $inRange === false
                ? CrawlerVerification::forged($crawler, CrawlerVerification::RANGE_EVIDENCE)
                : CrawlerVerification::unverifiable($crawler);
        }

        // DNS is the primary method; a list can add a verification but never a contradiction.
        return $byDns;
    }

    public function forget(string $ip, string $crawler): void
    {
        try {
            $this->cache?->forget(self::CACHE_PREFIX.$this->keyPart($crawler, $ip));
            $this->cache?->forget(self::PENDING_PREFIX.$this->keyPart($crawler, $ip));
        } catch (\Throwable) {
        }
    }

    /**
     * @param  list<string>  $suffixes
     */
    private function verifyByDns(string $ip, string $crawler, array $suffixes): CrawlerVerification
    {
        try {
            $hostname = $this->dns?->reverse($ip);

            if ($hostname === null || $hostname === '') {
                // "We could not ask", not "the claim is false": a resolver outage must not
                // reclassify every search engine as a forger.
                return CrawlerVerification::unverifiable($crawler);
            }

            if (! HostnameSuffix::matches($hostname, $suffixes)) {
                return CrawlerVerification::forged($crawler, $hostname);
            }

            $addresses = $this->dns?->forward($hostname) ?? [];
            if ($addresses === []) {
                return CrawlerVerification::unverifiable($crawler);
            }

            foreach ($addresses as $address) {
                if (is_string($address) && IpAddress::same($address, $ip)) {
                    return CrawlerVerification::verified($crawler, $hostname);
                }
            }

            // The PTR points at a vendor domain but that name does not resolve back here.
            return CrawlerVerification::forged($crawler, $hostname);
        } catch (\Throwable) {
            return CrawlerVerification::unverifiable($crawler);
        }
    }

    private function canDecide(string $crawler): bool
    {
        $definition = $this->catalogue->get($crawler);
        if ($definition === null || $definition->isMonitor()) {
            return false;
        }

        return ($definition->rdnsSuffixes !== [] && $this->dns !== null)
            || ($definition->hasRangeFeed() && $this->ranges !== null);
    }

    private function cached(string $ip, string $crawler): ?CrawlerVerification
    {
        try {
            $stored = $this->cache?->get(self::CACHE_PREFIX.$this->keyPart($crawler, $ip));
        } catch (\Throwable) {
            return null;
        }

        $verification = is_array($stored) ? CrawlerVerification::fromArray($stored) : null;

        // A cached entry must be about this crawler; anything else is a miss.
        return $verification !== null && $verification->crawler === $crawler ? $verification : null;
    }

    private function keyPart(string $crawler, string $ip): string
    {
        $packed = IpAddress::pack($ip);
        $canonical = $packed === null ? $ip : (string) inet_ntop($packed);
        $digest = $this->addressDigest === null ? hash('sha256', 'i:'.$canonical) : ($this->addressDigest)('i:'.$canonical);

        return $crawler.':'.$digest;
    }
}

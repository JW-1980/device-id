<?php

declare(strict_types=1);

namespace DeviceId\Crawlers;

/**
 * Vendor-published IP lists, fetched through the host's `RangeFetcher` and kept in its cache.
 *
 * Three answers, kept distinct:
 *  - `true`  the address is inside a published prefix;
 *  - `false` a list was read and the address is not in it;
 *  - `null`  no list is available (no feed configured, never fetched, or every fetch failed).
 * Callers fail closed on `null`: nothing is allowed because a list could not be read.
 *
 * ## Stale-while-failing
 *
 * A fetched list is stored with the time it was fetched and kept for `staleTtl` (30 days). After
 * `freshTtl` (24 h) it is stale: a refresh is attempted, and if every fetch fails the last good list
 * is KEPT and still used. A vendor outage therefore neither erases a working allowlist nor turns it
 * into "everything unlisted"; with no list at all the answer is `null`.
 *
 * ## Where fetching happens
 *
 * `contains()` on the request path must pass `$fetch = false`: it then only reads the cache. The
 * fetch belongs to a background step (`refresh()`, `refreshIfStale()`), because it is a blocking
 * network call.
 */
final class IpRangeDirectory
{
    private const CACHE_PREFIX = 'device-id:ranges:';

    private const ATTEMPT_PREFIX = 'device-id:ranges-attempt:';

    /** @var array<string, list<string>> per-process store when no cache is configured */
    private array $memory = [];

    /** @var array<string, int> */
    private array $memoryFetchedAt = [];

    /**
     * @param  (\Closure(): int)|null  $clock  unix seconds; for tests
     */
    public function __construct(
        private readonly CrawlerCatalogue $catalogue,
        private readonly ?RangeFetcher $fetcher = null,
        private readonly ?CrawlerCache $cache = null,
        private readonly int $freshTtl = 86400,
        private readonly int $staleTtl = 2592000,
        private readonly int $retryAfter = 300,
        private readonly ?\Closure $clock = null,
    ) {}

    public function hasFeed(string $key): bool
    {
        return $this->catalogue->get($key)?->hasRangeFeed() === true;
    }

    /**
     * @param  bool  $fetch  false on the request path: read the cache only
     */
    public function contains(string $key, string $ip, bool $fetch = false): ?bool
    {
        $packed = IpAddress::pack($ip);
        if ($packed === null) {
            return null;
        }

        $prefixes = $this->prefixes($key, $fetch);
        if ($prefixes === null) {
            return null;
        }

        foreach ($prefixes as $prefix) {
            $parsed = IpAddress::parseCidr($prefix);
            if ($parsed !== null && IpAddress::packedInCidr($packed, $parsed[0], $parsed[1])) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>|null canonical CIDRs, or null when no list is available
     */
    public function prefixes(string $key, bool $fetch = false): ?array
    {
        $entry = $this->read($key);

        if ($entry !== null && ! $this->isStaleEntry($entry['fetched_at'])) {
            return $entry['prefixes'];
        }

        if ($fetch) {
            $refreshed = $this->refresh($key);
            if ($refreshed !== null) {
                return $refreshed;
            }
        }

        // Stale-while-failing: the last good list outlives its freshness.
        return $entry['prefixes'] ?? null;
    }

    public function isStale(string $key): bool
    {
        $entry = $this->read($key);

        return $entry === null || $this->isStaleEntry($entry['fetched_at']);
    }

    /**
     * Fetch now. On success the list is stored; on total failure the previous list is untouched.
     *
     * @return list<string>|null the fresh list, or null when nothing could be fetched
     */
    public function refresh(string $key): ?array
    {
        $definition = $this->catalogue->get($key);
        if ($definition === null || $this->fetcher === null || ! $definition->hasRangeFeed()) {
            return null;
        }

        $prefixes = [];
        $anyRead = false;

        foreach ($definition->rangeUrls as $url) {
            try {
                $body = $this->fetcher->fetch($url);
            } catch (\Throwable) {
                $body = null;
            }

            if ($body === null) {
                continue;
            }

            $parsed = self::parse($body, $definition->rangePaths);
            if ($parsed === []) {
                // A 2xx body with no prefix in it is not a list; it must not replace a good one.
                continue;
            }

            $anyRead = true;
            array_push($prefixes, ...$parsed);
        }

        if (! $anyRead) {
            return null;
        }

        // Partial success is accepted (a vendor with several files): a missing file leaves a claim
        // undecided or unlisted, it never allows anything the files read did not.
        $prefixes = array_values(array_unique($prefixes));
        $this->write($key, $prefixes);

        return $prefixes;
    }

    /**
     * Refresh when stale, at most once per `retryAfter` seconds across processes.
     *
     * @return bool true when a fresh list is now available
     */
    public function refreshIfStale(string $key): bool
    {
        if (! $this->isStale($key)) {
            return true;
        }

        if ($this->cache !== null) {
            try {
                if (! $this->cache->add(self::ATTEMPT_PREFIX.$key, ['t' => $this->currentTime()], max(1, $this->retryAfter))) {
                    return false;
                }
            } catch (\Throwable) {
                // Proceed: an extra fetch is smaller than never refreshing.
            }
        }

        return $this->refresh($key) !== null;
    }

    public function forget(string $key): void
    {
        unset($this->memory[$key], $this->memoryFetchedAt[$key]);
        try {
            $this->cache?->forget(self::CACHE_PREFIX.$key);
        } catch (\Throwable) {
        }
    }

    /**
     * Every valid prefix in a feed body. JSON with `$paths` takes only those paths (arrays of
     * addresses or CIDRs); other JSON takes every CIDR string anywhere in the document; anything else
     * is read as text, splitting on whitespace, commas and semicolons, `#` starting a comment.
     * Invalid tokens, and any /0 prefix, are dropped.
     *
     * @param  list<string>  $paths  dot paths
     * @return list<string>
     */
    public static function parse(string $body, array $paths = []): array
    {
        $body = trim($body);
        if ($body === '') {
            return [];
        }

        $found = [];
        $add = static function (string $token) use (&$found): void {
            $normal = IpAddress::normalise($token);
            if ($normal !== null) {
                $found[$normal] = true;
            }
        };

        if ($body[0] === '{' || $body[0] === '[') {
            $data = json_decode($body, true);
            if (! is_array($data)) {
                return [];
            }

            if ($paths !== []) {
                foreach ($paths as $path) {
                    $node = $data;
                    foreach (explode('.', $path) as $segment) {
                        $node = is_array($node) && array_key_exists($segment, $node) ? $node[$segment] : null;
                    }
                    if (is_array($node)) {
                        array_walk_recursive($node, static function (mixed $value) use ($add): void {
                            if (is_string($value)) {
                                $add($value);
                            }
                        });
                    }
                }
            } else {
                array_walk_recursive($data, static function (mixed $value) use ($add): void {
                    if (is_string($value) && str_contains($value, '/')) {
                        $add($value);
                    }
                });
            }

            return array_keys($found);
        }

        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            $line = explode('#', $line, 2)[0];
            foreach (preg_split('/[\s,;]+/', $line, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $token) {
                $add($token);
            }
        }

        return array_keys($found);
    }

    /**
     * @return array{fetched_at: int, prefixes: list<string>}|null
     */
    private function read(string $key): ?array
    {
        if ($this->cache === null) {
            return isset($this->memory[$key])
                ? ['fetched_at' => $this->memoryFetchedAt[$key], 'prefixes' => $this->memory[$key]]
                : null;
        }

        try {
            $stored = $this->cache->get(self::CACHE_PREFIX.$key);
        } catch (\Throwable) {
            return null;
        }

        $at = $stored['fetched_at'] ?? null;
        $prefixes = $stored['prefixes'] ?? null;
        if (! is_int($at) || ! is_array($prefixes)) {
            return null;
        }

        $clean = array_values(array_filter($prefixes, static fn (mixed $p): bool => is_string($p) && IpAddress::isCidr($p)));

        return $clean === [] ? null : ['fetched_at' => $at, 'prefixes' => $clean];
    }

    /**
     * @param  list<string>  $prefixes
     */
    private function write(string $key, array $prefixes): void
    {
        $this->memory[$key] = $prefixes;
        $this->memoryFetchedAt[$key] = $this->currentTime();

        if ($this->cache === null) {
            return;
        }

        try {
            $this->cache->put(self::CACHE_PREFIX.$key, ['fetched_at' => $this->currentTime(), 'prefixes' => $prefixes], max(1, $this->staleTtl));
        } catch (\Throwable) {
        }
    }

    private function isStaleEntry(int $fetchedAt): bool
    {
        return $this->currentTime() - $fetchedAt >= $this->freshTtl;
    }

    private function currentTime(): int
    {
        return $this->clock === null ? time() : ($this->clock)();
    }
}

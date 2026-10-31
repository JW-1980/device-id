<?php

declare(strict_types=1);

namespace DeviceId\Reputation;

use DeviceId\Crawlers\CrawlerCache;
use DeviceId\Crawlers\RangeFetcher;

/**
 * IP reputation from free, published feeds: a loader (host-driven refresh through the same
 * {@see RangeFetcher} and {@see CrawlerCache} the crawler verification uses) and a matcher.
 *
 * ## Fail safe
 *
 * - Lookups read the cache only; a fetch is a blocking network call and belongs to a scheduled
 *   job (`refreshStale()`), never to a request.
 * - A feed older than `maxAgeSeconds` (7 days) is IGNORED, not used: a list that stopped
 *   updating is no evidence about today's traffic. Between `freshSeconds` (24 h) and the maximum
 *   it is still used and a refresh is due (stale-while-failing). The result says which feeds
 *   were unusable; silence from them is never read as "clean".
 * - A fetch that fails or parses to nothing leaves the previous list untouched, and a feed is
 *   not fetched again before its `minimumRefreshSeconds`.
 * - A feed whose licence is `unverified` is not loaded unless the host named it in
 *   `$acceptUnverified`; `not_compatible` is never loaded.
 */
final class IpReputation
{
    private const CACHE_PREFIX = 'device-id:reputation:';

    private const ATTEMPT_PREFIX = 'device-id:reputation-attempt:';

    /** @var array<string, array{fetched_at: int, set: PrefixSet}> */
    private array $sets = [];

    /**
     * @param  array<string, FeedDefinition>  $feeds
     * @param  list<string>  $acceptUnverified  feed keys the host has accepted despite an unverified licence
     * @param  (\Closure(): int)|null  $clock
     */
    public function __construct(
        private readonly array $feeds,
        private readonly ?RangeFetcher $fetcher = null,
        private readonly ?CrawlerCache $cache = null,
        private readonly array $acceptUnverified = [],
        private readonly int $freshSeconds = 86400,
        private readonly int $maxAgeSeconds = 604800,
        private readonly ?\Closure $clock = null,
    ) {}

    /**
     * @return array<string, FeedDefinition> the feeds this instance may load
     */
    public function enabledFeeds(): array
    {
        return array_filter($this->feeds, fn (FeedDefinition $feed): bool => $feed->isUsableWithout()
            || ($feed->licence['status'] === FeedDefinition::LICENCE_UNVERIFIED && in_array($feed->key, $this->acceptUnverified, true)));
    }

    /**
     * Fetch one feed now. True when a fresh list was stored.
     */
    public function refresh(string $key): bool
    {
        $feed = $this->enabledFeeds()[$key] ?? null;
        if ($feed === null || $this->fetcher === null || $this->cache === null) {
            return false;
        }

        $now = $this->currentTime();
        $attempt = $this->cache->get(self::ATTEMPT_PREFIX.$key);
        if (is_array($attempt) && $now - (int) ($attempt['at'] ?? 0) < $feed->minimumRefreshSeconds) {
            return false;
        }
        $this->cache->put(self::ATTEMPT_PREFIX.$key, ['at' => $now], $feed->minimumRefreshSeconds);

        $body = $this->fetchBody($feed);
        $prefixes = $body === null ? null : FeedParser::parse($feed->format, $body);
        if ($prefixes === null) {
            return false;
        }

        $this->cache->put(self::CACHE_PREFIX.$key, ['fetched_at' => $now, 'prefixes' => $prefixes], $this->maxAgeSeconds * 4);
        unset($this->sets[$key]);

        return true;
    }

    /**
     * The body to parse. A directory feed (CollecTor) is two fetches: the index, then its newest
     * file; either failing is a failed refresh, never a partial one.
     */
    private function fetchBody(FeedDefinition $feed): ?string
    {
        $body = $this->fetcher?->fetch($feed->url);
        if ($body === null || $feed->format !== FeedDefinition::FORMAT_TORDNSEL_DIRECTORY) {
            return $body;
        }
        $name = FeedParser::newestExitListName($body);

        return $name === null ? null : $this->fetcher?->fetch(rtrim($feed->url, '/').'/'.$name);
    }

    /**
     * Refresh every enabled feed that is missing or older than the fresh window.
     *
     * @return array<string, string> key => `refreshed`, `fresh`, `failed`
     */
    public function refreshStale(): array
    {
        $out = [];
        foreach (array_keys($this->enabledFeeds()) as $key) {
            $entry = $this->cache?->get(self::CACHE_PREFIX.$key);
            if (is_array($entry) && $this->currentTime() - (int) ($entry['fetched_at'] ?? 0) < $this->freshSeconds) {
                $out[$key] = 'fresh';

                continue;
            }
            $out[$key] = $this->refresh($key) ? 'refreshed' : 'failed';
        }

        return $out;
    }

    public function lookup(string $ip): ReputationResult
    {
        $categories = $sources = $unusable = $attribution = [];
        $usable = 0;

        foreach ($this->enabledFeeds() as $key => $feed) {
            $set = $this->setFor($key);
            if ($set === null) {
                $unusable[] = $key;

                continue;
            }
            $usable++;
            if ($set->contains($ip)) {
                $categories[$feed->category] = true;
                $sources[] = $key;
                if ($feed->attribution !== '') {
                    $attribution[$feed->attribution] = true;
                }
            }
        }

        $fixed = $this->fixedFeeds($unusable);

        if ($usable === 0) {
            return ReputationResult::unavailable($fixed);
        }

        return new ReputationResult($fixed === [] ? ReputationResult::STATE_OK : ReputationResult::STATE_PARTIAL, array_keys($categories), $sources, $fixed, array_keys($attribution));
    }

    /**
     * Feeds the host has not enabled (unaccepted licence) also count as unusable for the
     * purpose of `complete`.
     *
     * @param  list<string>  $unusable
     * @return list<string>
     */
    private function fixedFeeds(array $unusable): array
    {
        $disabled = array_diff(array_keys($this->feeds), array_keys($this->enabledFeeds()));
        $all = array_values(array_unique([...$unusable, ...$disabled]));
        sort($all);

        return $all;
    }

    private function setFor(string $key): ?PrefixSet
    {
        $entry = $this->cache?->get(self::CACHE_PREFIX.$key);
        if (! is_array($entry) || ! is_array($entry['prefixes'] ?? null) || ! is_int($entry['fetched_at'] ?? null)) {
            return null;
        }
        if ($this->currentTime() - $entry['fetched_at'] > $this->maxAgeSeconds) {
            return null;
        }
        if (($this->sets[$key]['fetched_at'] ?? null) !== $entry['fetched_at']) {
            $this->sets[$key] = ['fetched_at' => $entry['fetched_at'], 'set' => new PrefixSet(array_values(array_filter($entry['prefixes'], 'is_string')))];
        }

        return $this->sets[$key]['set'];
    }

    private function currentTime(): int
    {
        return $this->clock === null ? time() : ($this->clock)();
    }
}

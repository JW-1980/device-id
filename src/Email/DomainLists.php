<?php

declare(strict_types=1);

namespace DeviceId\Email;

use DeviceId\Crawlers\CrawlerCache;
use DeviceId\Crawlers\RangeFetcher;
use DeviceId\Network\NetworkDatabase;

/**
 * Local e-mail-domain lists: a loader (host-driven refresh through the same {@see RangeFetcher}
 * and {@see CrawlerCache} the network data uses) and a lookup that reads the cache only.
 *
 * ## Fail safe (the same rules as {@see NetworkDatabase})
 *
 * - **No network call on the request path.** {@see lookup()} reads cached buckets. A download
 *   belongs to a scheduled job ({@see refreshStale()}).
 * - **A list older than its maximum age is ignored**, and the answer is `null` (unknown), never
 *   `false` ("not disposable").
 * - **A refresh that fails or parses to almost nothing leaves the previous version in place**; the
 *   buckets of a new version are written before the manifest that points at them.
 * - **Publisher rate limits are kept** ({@see DomainFeed::$minimumRefreshSeconds}); a feed whose
 *   licence is not usable without a public credit is never loaded.
 *
 * ## Matching
 *
 * A domain is disposable when it, or a parent domain with at least two labels, is on a disposable
 * list (`x.mailinator.com` is covered by `mailinator.com`). Free providers and alias services are
 * matched exactly: a subdomain of a free provider says nothing.
 *
 * ## Cache layout
 *
 * `device-id:domains:<feed>:manifest` and `device-id:domains:<feed>:<version>:<category>:<bucket>`
 * (`crc32(domain) % 64`, so a lookup reads about 1,000 domains at most).
 */
final class DomainLists
{
    private const PREFIX = 'device-id:domains:';

    private const ATTEMPT_PREFIX = 'device-id:domains-attempt:';

    private const BUCKETS = 64;

    private const MAX_BODY_BYTES = 33554432;

    /** @var array<string, array{loaded: int, manifest: array<string, mixed>|null}> */
    private array $manifests = [];

    /** @var array<string, list<string>> */
    private array $buckets = [];

    /**
     * @param  array<string, DomainFeed>  $feeds
     * @param  (\Closure(): int)|null  $clock
     */
    public function __construct(
        private readonly array $feeds,
        private readonly ?RangeFetcher $fetcher = null,
        private readonly ?CrawlerCache $cache = null,
        private readonly ?\Closure $clock = null,
        private readonly int $minimumRecords = 50,
    ) {}

    public static function withDefaults(?RangeFetcher $fetcher = null, ?CrawlerCache $cache = null): self
    {
        return new self(DomainFeedCatalogue::defaults(), $fetcher, $cache);
    }

    /**
     * @return array<string, DomainFeed>
     */
    public function enabledFeeds(): array
    {
        return array_filter($this->feeds, static fn (DomainFeed $feed): bool => $feed->isUsableWithout());
    }

    // ------------------------------------------------------------------ refresh (a job, never a request)

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

        foreach ($feed->urls as $url) {
            $body = $this->fetcher->fetch($url);
            if ($body === null || $body === '' || strlen($body) > self::MAX_BODY_BYTES) {
                continue;
            }
            if ($this->store($feed, $body, $now)) {
                unset($this->manifests[$key]);

                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, string> key => `refreshed`, `fresh`, `failed`
     */
    public function refreshStale(): array
    {
        $out = [];
        foreach ($this->enabledFeeds() as $key => $feed) {
            $manifest = $this->manifest($key, false);
            if ($manifest !== null && $this->currentTime() - (int) $manifest['fetched_at'] < $feed->freshSeconds) {
                $out[$key] = 'fresh';

                continue;
            }
            $out[$key] = $this->refresh($key) ? 'refreshed' : 'failed';
        }

        return $out;
    }

    // ------------------------------------------------------------------ lookup (cache only)

    /**
     * @param  string  $domain  a mail domain; lower-cased and trimmed here
     */
    public function lookup(string $domain): DomainFacts
    {
        $domain = self::normaliseDomain($domain);
        $unusable = array_values(array_diff(array_keys($this->feeds), array_keys($this->enabledFeeds())));
        if ($domain === null) {
            return new DomainFacts(DomainFacts::STATE_UNAVAILABLE, unusable: $unusable);
        }

        /** @var array<string, bool|null> $answers */
        $answers = [DomainFeed::DISPOSABLE => null, DomainFeed::FREE => null, DomainFeed::FORWARDING => null];
        $usable = 0;

        foreach ($this->enabledFeeds() as $key => $feed) {
            $manifest = $this->manifest($key, true);
            if ($manifest === null) {
                $unusable[] = $key;

                continue;
            }
            $usable++;
            foreach ($feed->categories as $category) {
                $listed = $category === DomainFeed::DISPOSABLE
                    ? $this->listedWithParents($key, $manifest, $category, $domain)
                    : $this->listed($key, $manifest, $category, $domain);
                $answers[$category] = ($answers[$category] ?? false) || $listed;
            }
        }

        if ($usable === 0) {
            return new DomainFacts(DomainFacts::STATE_UNAVAILABLE, unusable: array_values(array_unique($unusable)));
        }

        return new DomainFacts(
            $unusable === [] ? DomainFacts::STATE_OK : DomainFacts::STATE_PARTIAL,
            $answers[DomainFeed::DISPOSABLE],
            $answers[DomainFeed::FREE],
            $answers[DomainFeed::FORWARDING],
            array_values(array_unique($unusable)),
        );
    }

    // ------------------------------------------------------------------ parsing (pure, public for tests)

    /**
     * @return list<string> lower-case domains, unique, in file order
     */
    public static function parseLines(string $text): array
    {
        $out = [];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            $line = strtolower(trim(explode('#', $line, 2)[0]));
            if ($line !== '' && preg_match('/^[a-z0-9]([a-z0-9._-]*[a-z0-9])?\.[a-z0-9-]{2,}$/', $line) === 1) {
                $out[$line] = true;
            }
        }

        return array_keys($out);
    }

    /**
     * The free mailbox providers and the alias or forwarding services of `mailservices.json`:
     * every provider key and every host of a provider of that type.
     *
     * @return array{free: list<string>, forwarding: list<string>}
     */
    public static function parseMailServices(string $json): array
    {
        $data = json_decode($json, true);
        $free = $forwarding = [];
        if (! is_array($data)) {
            return ['free' => [], 'forwarding' => []];
        }
        foreach ($data as $name => $provider) {
            if (! is_array($provider)) {
                continue;
            }
            $hosts = array_filter([(string) $name, ...(is_array($provider['hosts'] ?? null) ? $provider['hosts'] : [])], static fn (mixed $h): bool => is_string($h) && str_contains($h, '.'));
            $hosts = array_map('strtolower', $hosts);
            $type = $provider['type'] ?? null;
            $costs = $provider['costs'] ?? null;
            if ($type === 'mailbox' && in_array($costs, ['free', 'freemium'], true)) {
                foreach ($hosts as $host) {
                    $free[$host] = true;
                }
            } elseif ($type === 'forwarding') {
                foreach ($hosts as $host) {
                    $forwarding[$host] = true;
                }
            }
        }

        return ['free' => array_keys($free), 'forwarding' => array_keys($forwarding)];
    }

    public static function normaliseDomain(string $domain): ?string
    {
        $domain = rtrim(strtolower(trim($domain)), '.');
        if (function_exists('idn_to_ascii') && preg_match('/[^\x00-\x7f]/', $domain) === 1) {
            $ascii = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            $domain = is_string($ascii) ? $ascii : $domain;
        }

        return $domain !== '' && strlen($domain) <= 253 && str_contains($domain, '.') && preg_match('/^[a-z0-9._-]+$/', $domain) === 1 ? $domain : null;
    }

    // ------------------------------------------------------------------ internals

    private function store(DomainFeed $feed, string $body, int $now): bool
    {
        if ($this->cache === null) {
            return false;
        }
        /** @var array<string, list<string>> $byCategory */
        $byCategory = match ($feed->format) {
            DomainFeed::FORMAT_MAILSERVICES => self::parseMailServices($body),
            default => [DomainFeed::DISPOSABLE => self::parseLines($body)],
        };
        $total = 0;
        foreach ($feed->categories as $category) {
            $total += count($byCategory[$category] ?? []);
        }
        // A file that parses to almost nothing is a truncated or wrong download, not a list.
        if ($total < $this->minimumRecords) {
            return false;
        }

        $ttl = $feed->maxAgeSeconds * 2;
        $prefix = self::PREFIX.$feed->key;
        $counts = [];
        foreach ($feed->categories as $category) {
            $buckets = [];
            foreach ($byCategory[$category] ?? [] as $domain) {
                $buckets[self::bucketOf($domain)][] = $domain;
            }
            foreach ($buckets as $bucket => $domains) {
                $this->cache->put($prefix.':'.$now.':'.$category.':'.$bucket, ['d' => $domains], $ttl);
            }
            $counts[$category] = count($byCategory[$category] ?? []);
        }
        // The manifest goes last: until it is written readers keep the previous version.
        $this->cache->put($prefix.':manifest', ['fetched_at' => $now, 'counts' => $counts], $ttl);

        return true;
    }

    private static function bucketOf(string $domain): int
    {
        return crc32($domain) % self::BUCKETS;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function manifest(string $key, bool $enforceAge): ?array
    {
        $feed = $this->feeds[$key] ?? null;
        if ($feed === null || $this->cache === null) {
            return null;
        }
        $now = $this->currentTime();
        $memo = $this->manifests[$key] ?? null;
        if ($memo === null || $now - $memo['loaded'] > 60) {
            $entry = $this->cache->get(self::PREFIX.$key.':manifest');
            $memo = ['loaded' => $now, 'manifest' => is_array($entry) && is_int($entry['fetched_at'] ?? null) ? $entry : null];
            $this->manifests[$key] = $memo;
        }
        $manifest = $memo['manifest'];
        if ($manifest === null || ($enforceAge && $now - (int) $manifest['fetched_at'] > $feed->maxAgeSeconds)) {
            return null;
        }

        return $manifest;
    }

    /**
     * @param  array<string, mixed>  $manifest
     */
    private function listed(string $key, array $manifest, string $category, string $domain): bool
    {
        $bucket = self::bucketOf($domain);
        $cacheKey = self::PREFIX.$key.':'.$manifest['fetched_at'].':'.$category.':'.$bucket;
        if (! isset($this->buckets[$cacheKey])) {
            $entry = $this->cache?->get($cacheKey);
            if (count($this->buckets) >= 16) {
                $this->buckets = [];
            }
            $this->buckets[$cacheKey] = is_array($entry) && is_array($entry['d'] ?? null) ? array_values(array_filter($entry['d'], 'is_string')) : [];
        }

        return in_array($domain, $this->buckets[$cacheKey], true);
    }

    /**
     * @param  array<string, mixed>  $manifest
     */
    private function listedWithParents(string $key, array $manifest, string $category, string $domain): bool
    {
        $labels = explode('.', $domain);
        for ($i = 0; $i <= count($labels) - 2; $i++) {
            if ($this->listed($key, $manifest, $category, implode('.', array_slice($labels, $i)))) {
                return true;
            }
        }

        return false;
    }

    private function currentTime(): int
    {
        return $this->clock === null ? time() : ($this->clock)();
    }
}

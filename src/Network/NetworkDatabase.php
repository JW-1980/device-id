<?php

declare(strict_types=1);

namespace DeviceId\Network;

use DeviceId\Crawlers\CrawlerCache;
use DeviceId\Crawlers\IpAddress;
use DeviceId\Crawlers\RangeFetcher;

/**
 * Local IP to country and ASN data for the network signals: a loader (host-driven refresh
 * through the same {@see RangeFetcher} and {@see CrawlerCache} the crawler verification and
 * the IP reputation use) and a lookup that reads the cache only.
 *
 * ## Fail safe
 *
 * - **No network call on the request path.** {@see lookup()} reads cached shards. A download is a
 *   blocking call of up to ten megabytes and belongs to a scheduled job ({@see refreshStale()}).
 * - **A dataset older than its maximum age is ignored, not used**, and the result says which
 *   datasets were unusable: silence from them is never read as "domestic" or "clean".
 * - **A refresh that fails or parses to nothing leaves the previous data in place.** The shards
 *   of a new version are written before the manifest that points at them, so a reader sees the
 *   old version or the new one, never a mixture, and an interrupted refresh changes nothing.
 * - **Rate limits of the publishers are kept** ({@see NetworkFeed::$minimumRefreshSeconds}).
 * - An unverified or incompatible licence is not loaded unless the host named the feed.
 * - A refresh needs `ext-zlib` for the `.gz` files and roughly 200 MB of memory (the IPtoASN
 *   file is 50 MB of text); a host runs it from a command line job, not from a web request.
 *
 * ## Cache layout
 *
 * `device-id:net:<feed>:manifest` (the current version and which shards exist) and
 * `device-id:net:<feed>:<version>:<shard>` (a {@see RangeTable} shard, base64 so a JSON-backed
 * cache stores it too). Superseded versions are not deleted, they expire by TTL.
 */
final class NetworkDatabase
{
    private const PREFIX = 'device-id:net:';

    private const ATTEMPT_PREFIX = 'device-id:net-attempt:';

    private const MAX_INFLATED_BYTES = 268435456;

    private const COUNTRY_LENGTH = 2;

    private const ASN_LENGTH = 4;

    /** @var array<string, array{loaded: int, manifest: array<string, mixed>|null}> */
    private array $manifests = [];

    /** @var array<string, string> */
    private array $shards = [];

    /** @var array<string, array{h: string, v: string}> */
    private array $flags = [];

    /**
     * @param  array<string, NetworkFeed>  $feeds
     * @param  list<string>  $acceptUnverified  feed keys the host accepts despite an unverified licence
     * @param  (\Closure(): int)|null  $clock
     */
    public function __construct(
        private readonly array $feeds,
        private readonly ?RangeFetcher $fetcher = null,
        private readonly ?CrawlerCache $cache = null,
        private readonly array $acceptUnverified = [],
        private readonly ?\Closure $clock = null,
        private readonly int $minimumRecords = 1000,
    ) {}

    public static function withDefaults(?RangeFetcher $fetcher = null, ?CrawlerCache $cache = null): self
    {
        return new self(NetworkFeedCatalogue::defaults(), $fetcher, $cache);
    }

    /**
     * @return array<string, NetworkFeed> the feeds this instance may load
     */
    public function enabledFeeds(): array
    {
        return array_filter($this->feeds, fn (NetworkFeed $feed): bool => $feed->isUsableWithout()
            || ($feed->licence['status'] === 'unverified' && in_array($feed->key, $this->acceptUnverified, true)));
    }

    // ------------------------------------------------------------------ refresh (a job, never a request)

    /**
     * Fetch one feed now. True when a fresh version was stored.
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

        foreach ($this->urlsFor($feed, $now) as $url) {
            $body = $this->fetcher->fetch($url);
            if ($body === null) {
                continue;
            }
            $text = self::inflate($body);
            if ($text === null) {
                continue;
            }
            if ($this->store($feed, $text, $now)) {
                unset($this->manifests[$key]);

                return true;
            }
        }

        return false;
    }

    /**
     * Refresh every enabled feed that is missing or older than its fresh window.
     *
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

    public function lookup(string $ip): NetworkFacts
    {
        $packed = IpAddress::pack($ip);
        $feeds = $this->enabledFeeds();
        $unusable = array_values(array_diff(array_keys($this->feeds), array_keys($feeds)));
        if ($packed === null) {
            return new NetworkFacts(NetworkFacts::STATE_UNAVAILABLE, null, null, null, false, false, array_keys($feeds));
        }

        $country = $asn = $category = null;
        $attribution = [];
        $usable = 0;

        foreach ($feeds as $key => $feed) {
            $manifest = $this->manifest($key, true);
            if ($manifest === null) {
                $unusable[] = $key;

                continue;
            }
            $usable++;

            switch ($feed->kind) {
                case NetworkFeed::KIND_COUNTRY:
                    $value = $this->find($key, $manifest, $packed, self::COUNTRY_LENGTH);
                    if ($value !== null && preg_match('/^[A-Z]{2}$/', $value) === 1) {
                        $country = $value;
                        if ($feed->attribution !== '') {
                            $attribution[] = $feed->attribution;
                        }
                    }
                    break;
                case NetworkFeed::KIND_ASN:
                    $value = $this->find($key, $manifest, $packed, self::ASN_LENGTH);
                    if ($value !== null) {
                        /** @var array{1: int} $unpacked */
                        $unpacked = unpack('N', $value);
                        $asn = $unpacked[1] === 0 ? null : $unpacked[1];
                        if ($asn !== null) {
                            $flags = $this->flagsOf($key, $manifest);
                            $category = self::contains($flags['v'], $asn) ? NetworkFacts::CATEGORY_VPN
                                : (self::contains($flags['h'], $asn) ? NetworkFacts::CATEGORY_HOSTING : $category);
                        }
                    }
                    break;
                default:
                    break;
            }
        }

        // The list of hosting ASNs needs the ASN, so it is read after the loop.
        if ($asn !== null && $category === null) {
            foreach ($feeds as $key => $feed) {
                if ($feed->kind !== NetworkFeed::KIND_HOSTING_ASN_LIST) {
                    continue;
                }
                $manifest = $this->manifest($key, true);
                if ($manifest !== null && self::contains(base64_decode((string) ($manifest['asns'] ?? ''), true) ?: '', $asn)) {
                    $category = NetworkFacts::CATEGORY_HOSTING;
                    if ($feed->attribution !== '') {
                        $attribution[] = $feed->attribution;
                    }
                }
            }
        }

        if ($usable === 0) {
            return new NetworkFacts(NetworkFacts::STATE_UNAVAILABLE, null, null, null, false, false, array_values(array_unique($unusable)));
        }

        return new NetworkFacts(
            $unusable === [] ? NetworkFacts::STATE_OK : NetworkFacts::STATE_PARTIAL,
            $country, $asn, $category, false, false,
            array_values(array_unique($unusable)),
            array_values(array_unique($attribution)),
        );
    }

    /**
     * The credit lines the enabled datasets require, for a host's notice page.
     *
     * @return list<string>
     */
    public function attribution(): array
    {
        $lines = [];
        foreach ($this->enabledFeeds() as $feed) {
            if ($feed->attribution !== '') {
                $lines[] = $feed->attribution;
            }
        }

        return $lines;
    }

    // ------------------------------------------------------------------ parsing (pure, public for tests)

    /**
     * `start,end,CC` lines (DB-IP). Reserved ranges (`ZZ`) are dropped, not stored as a country.
     *
     * @return array{shards: array<string, string>, records: int}
     */
    public static function parseCountryCsv(string $text): array
    {
        $buffers = [];
        $records = 0;
        $lastEnd = [];
        self::eachLine($text, static function (string $line) use (&$buffers, &$records, &$lastEnd): void {
            $parts = explode(',', $line);
            if (count($parts) < 3) {
                return;
            }
            $country = strtoupper(trim($parts[2], " \"\r"));
            if (preg_match('/^[A-Z]{2}$/', $country) !== 1 || $country === 'ZZ') {
                return;
            }
            if (self::addRange($buffers, $lastEnd, trim($parts[0], ' "'), trim($parts[1], ' "'), $country)) {
                $records++;
            }
        });

        return ['shards' => $buffers, 'records' => $records];
    }

    /**
     * `start end ASN country name` lines (IPtoASN, tab separated). Not-routed space (ASN 0) is
     * dropped. The registered name is classified once per ASN and not stored.
     *
     * @return array{shards: array<string, string>, records: int, vpn: list<int>, hosting: list<int>}
     */
    public static function parseAsnTsv(string $text): array
    {
        $buffers = [];
        $records = 0;
        $lastEnd = [];
        $category = [];
        self::eachLine($text, static function (string $line) use (&$buffers, &$records, &$lastEnd, &$category): void {
            $parts = explode("\t", $line, 5);
            if (count($parts) < 3 || ! ctype_digit($parts[2])) {
                return;
            }
            $asn = (int) $parts[2];
            if ($asn === 0 || $asn > 4294967295) {
                return;
            }
            if (! array_key_exists($asn, $category)) {
                $category[$asn] = AsnClassifier::classify($parts[4] ?? '');
            }
            if (self::addRange($buffers, $lastEnd, $parts[0], $parts[1], pack('N', $asn))) {
                $records++;
            }
        });

        $vpn = $hosting = [];
        foreach ($category as $asn => $value) {
            if ($value === NetworkFacts::CATEGORY_VPN) {
                $vpn[] = $asn;
            } elseif ($value === NetworkFacts::CATEGORY_HOSTING) {
                $hosting[] = $asn;
            }
        }
        sort($vpn);
        sort($hosting);

        return ['shards' => $buffers, 'records' => $records, 'vpn' => $vpn, 'hosting' => $hosting];
    }

    /**
     * `ASN,Entity` lines with a header (bad-asn-list).
     *
     * @return list<int> sorted, unique
     */
    public static function parseAsnList(string $text): array
    {
        $asns = [];
        self::eachLine($text, static function (string $line) use (&$asns): void {
            $first = trim(explode(',', $line, 2)[0], " \"\r");
            if (ctype_digit($first) && (int) $first > 0 && (int) $first <= 4294967295) {
                $asns[(int) $first] = true;
            }
        });
        $out = array_keys($asns);
        sort($out);

        return $out;
    }

    // ------------------------------------------------------------------ internals

    /**
     * @param  array<string, string>  $buffers
     * @param  array<int, string>  $lastEnd  per address family, the end of the previous range
     */
    private static function addRange(array &$buffers, array &$lastEnd, string $start, string $end, string $value): bool
    {
        $a = IpAddress::pack($start);
        $b = IpAddress::pack($end);
        if ($a === null || $b === null || strlen($a) !== strlen($b) || strcmp($a, $b) > 0) {
            return false;
        }
        $family = strlen($a);
        if (isset($lastEnd[$family]) && strcmp($a, $lastEnd[$family]) <= 0) {
            return false;
        }
        $lastEnd[$family] = $b;
        RangeTable::add($buffers, $a, $b, $value);

        return true;
    }

    /**
     * @param  \Closure(string): void  $each
     */
    private static function eachLine(string $text, \Closure $each): void
    {
        $offset = 0;
        $length = strlen($text);
        while ($offset < $length) {
            $newline = strpos($text, "\n", $offset);
            $end = $newline === false ? $length : $newline;
            if ($end > $offset) {
                $each(rtrim(substr($text, $offset, $end - $offset), "\r"));
            }
            $offset = $end + 1;
        }
    }

    private static function inflate(string $body): ?string
    {
        if (str_starts_with($body, "\x1f\x8b")) {
            if (! function_exists('gzdecode')) {
                return null;
            }
            $text = @gzdecode($body, self::MAX_INFLATED_BYTES);

            return $text === false ? null : $text;
        }

        return $body === '' ? null : $body;
    }

    /**
     * @return list<string>
     */
    private function urlsFor(NetworkFeed $feed, int $now): array
    {
        $urls = [];
        foreach ($feed->urls as $pattern) {
            if (! str_contains($pattern, '{YYYY-MM}')) {
                $urls[] = $pattern;

                continue;
            }
            $thisMonth = new \DateTimeImmutable('@'.$now);
            $urls[] = str_replace('{YYYY-MM}', $thisMonth->format('Y-m'), $pattern);
            $urls[] = str_replace('{YYYY-MM}', $thisMonth->modify('first day of last month')->format('Y-m'), $pattern);
        }

        return $urls;
    }

    private function store(NetworkFeed $feed, string $text, int $now): bool
    {
        if ($this->cache === null) {
            return false;
        }
        $ttl = $feed->maxAgeSeconds * 2;
        $prefix = self::PREFIX.$feed->key;

        if ($feed->kind === NetworkFeed::KIND_HOSTING_ASN_LIST) {
            $asns = self::parseAsnList($text);
            if ($asns === []) {
                return false;
            }
            $this->cache->put($prefix.':manifest', ['fetched_at' => $now, 'asns' => base64_encode(pack('N*', ...$asns)), 'records' => count($asns)], $ttl);

            return true;
        }

        $parsed = $feed->kind === NetworkFeed::KIND_COUNTRY ? self::parseCountryCsv($text) : self::parseAsnTsv($text);
        // A file that parses to almost nothing is a truncated or wrong download, not a dataset.
        if ($parsed['records'] < $this->minimumRecords) {
            return false;
        }

        foreach ($parsed['shards'] as $shard => $data) {
            $this->cache->put($prefix.':'.$now.':'.$shard, ['d' => base64_encode($data)], $ttl);
        }
        if ($feed->kind === NetworkFeed::KIND_ASN && isset($parsed['vpn'], $parsed['hosting'])) {
            $this->cache->put($prefix.':'.$now.':flags', [
                'v' => base64_encode(pack('N*', ...$parsed['vpn'])),
                'h' => base64_encode(pack('N*', ...$parsed['hosting'])),
            ], $ttl);
        }
        // The manifest goes last: until it is written readers keep the previous version.
        $this->cache->put($prefix.':manifest', ['fetched_at' => $now, 'shards' => array_keys($parsed['shards']), 'records' => $parsed['records']], $ttl);

        return true;
    }

    /**
     * The current manifest, or null when absent, or (with $enforceAge) older than the maximum age.
     *
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
    private function find(string $key, array $manifest, string $packed, int $valueLength): ?string
    {
        $shard = RangeTable::shardOf($packed);
        if (! in_array($shard, (array) ($manifest['shards'] ?? []), true)) {
            return null;
        }
        $cacheKey = self::PREFIX.$key.':'.$manifest['fetched_at'].':'.$shard;
        if (! isset($this->shards[$cacheKey])) {
            $entry = $this->cache?->get($cacheKey);
            $data = is_array($entry) && is_string($entry['d'] ?? null) ? base64_decode($entry['d'], true) : false;
            if ($data === false) {
                return null;
            }
            if (count($this->shards) >= 8) {
                $this->shards = [];
            }
            $this->shards[$cacheKey] = $data;
        }

        return RangeTable::find($this->shards[$cacheKey], $packed, $valueLength);
    }

    /**
     * @param  array<string, mixed>  $manifest
     * @return array{h: string, v: string}
     */
    private function flagsOf(string $key, array $manifest): array
    {
        $cacheKey = self::PREFIX.$key.':'.$manifest['fetched_at'].':flags';
        if (! isset($this->flags[$cacheKey])) {
            $entry = $this->cache?->get($cacheKey);
            $this->flags[$cacheKey] = [
                'h' => is_array($entry) && is_string($entry['h'] ?? null) ? (base64_decode($entry['h'], true) ?: '') : '',
                'v' => is_array($entry) && is_string($entry['v'] ?? null) ? (base64_decode($entry['v'], true) ?: '') : '',
            ];
        }

        return $this->flags[$cacheKey];
    }

    /**
     * Binary search in a sorted `pack('N*')` string.
     */
    private static function contains(string $packedAsns, int $asn): bool
    {
        $low = 0;
        $high = intdiv(strlen($packedAsns), 4) - 1;
        while ($low <= $high) {
            $mid = ($low + $high) >> 1;
            /** @var array{1: int} $value */
            $value = unpack('N', $packedAsns, $mid * 4);
            if ($value[1] === $asn) {
                return true;
            }
            if ($value[1] < $asn) {
                $low = $mid + 1;
            } else {
                $high = $mid - 1;
            }
        }

        return false;
    }

    private function currentTime(): int
    {
        return $this->clock === null ? time() : ($this->clock)();
    }
}

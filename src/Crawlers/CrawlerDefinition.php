<?php

declare(strict_types=1);

namespace DeviceId\Crawlers;

/**
 * One known automated client and the ways its identity can be proven.
 *
 * A User-Agent token only ever says what a client CLAIMS to be. The proof is one of:
 *
 *  - `rdnsSuffixes`: the client address reverse-resolves to a name under one of these domains and
 *    that name resolves forward to the same address (kind `crawler`);
 *  - `rangeUrls`: the client address is inside a prefix the vendor publishes at these HTTPS URLs.
 *    `rangePaths` names the JSON paths (`synthetics.prefixes_ipv4`) that hold the prefixes when the
 *    document also carries other products' ranges; empty means a plain-text list or a JSON document
 *    in which every CIDR string is a prefix.
 *
 * With neither, the definition is config-only: the claim is recognised but never provable, and the
 * host's operator allowlist is the only way to allow it.
 */
final readonly class CrawlerDefinition
{
    public const KIND_CRAWLER = 'crawler';

    public const KIND_MONITOR = 'monitor';

    /**
     * @param  list<string>  $uaTokens  lower-case substrings of the User-Agent
     * @param  list<string>  $rdnsSuffixes
     * @param  list<string>  $rangeUrls  HTTPS only; other schemes are dropped
     * @param  list<string>  $rangePaths
     */
    public function __construct(
        public string $key,
        public string $label,
        public string $kind = self::KIND_CRAWLER,
        public array $uaTokens = [],
        public array $rdnsSuffixes = [],
        public array $rangeUrls = [],
        public array $rangePaths = [],
    ) {}

    /**
     * @param  array<array-key, mixed>  $data  keys: label, kind, ua_tokens, verify_domains, ip_ranges, range_paths
     */
    public static function fromArray(string $key, array $data): self
    {
        $list = static function (mixed $value): array {
            if (! is_array($value)) {
                return [];
            }

            return array_values(array_filter(
                array_map(static fn (mixed $item): string => is_string($item) ? trim($item) : '', $value),
                static fn (string $item): bool => $item !== '',
            ));
        };

        $kind = ($data['kind'] ?? null) === self::KIND_MONITOR ? self::KIND_MONITOR : self::KIND_CRAWLER;
        $label = is_string($data['label'] ?? null) && $data['label'] !== '' ? $data['label'] : $key;

        return new self(
            $key,
            $label,
            $kind,
            array_map('strtolower', $list($data['ua_tokens'] ?? [])),
            $list($data['verify_domains'] ?? []),
            array_values(array_filter($list($data['ip_ranges'] ?? []), static fn (string $url): bool => str_starts_with($url, 'https://'))),
            $list($data['range_paths'] ?? []),
        );
    }

    public function claimedBy(string $lowerCaseUserAgent): bool
    {
        foreach ($this->uaTokens as $token) {
            if ($token !== '' && str_contains($lowerCaseUserAgent, $token)) {
                return true;
            }
        }

        return false;
    }

    public function hasRangeFeed(): bool
    {
        return $this->rangeUrls !== [];
    }

    public function isMonitor(): bool
    {
        return $this->kind === self::KIND_MONITOR;
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Crawlers;

use NutriCompare\Fingerprint\Crawlers\ArrayCache;
use NutriCompare\Fingerprint\Crawlers\CrawlerCatalogue;
use NutriCompare\Fingerprint\Crawlers\CrawlerVerifier;
use NutriCompare\Fingerprint\Crawlers\DnsResolver;
use NutriCompare\Fingerprint\Crawlers\IpRangeDirectory;
use NutriCompare\Fingerprint\Crawlers\RangeFetcher;
use PHPUnit\Framework\TestCase;

/** A DNS with scripted answers. Anything not scripted is "no answer". */
final class FakeDns implements DnsResolver
{
    public int $reverseCalls = 0;

    public bool $throws = false;

    /**
     * @param  array<string, string>  $ptr  ip => hostname
     * @param  array<string, list<string>>  $a  hostname => addresses
     */
    public function __construct(public array $ptr = [], public array $a = []) {}

    public function reverse(string $ip): ?string
    {
        $this->reverseCalls++;
        if ($this->throws) {
            throw new \RuntimeException('resolver down');
        }

        return $this->ptr[$ip] ?? null;
    }

    public function forward(string $hostname): array
    {
        if ($this->throws) {
            throw new \RuntimeException('resolver down');
        }

        return $this->a[$hostname] ?? [];
    }
}

/** A fetcher with scripted bodies; a missing URL, or `$down`, is a failed fetch. */
final class FakeFetcher implements RangeFetcher
{
    public int $calls = 0;

    public bool $down = false;

    /** @param  array<string, string>  $bodies  url => body */
    public function __construct(public array $bodies = []) {}

    public function fetch(string $url): ?string
    {
        $this->calls++;

        return $this->down ? null : ($this->bodies[$url] ?? null);
    }
}

abstract class CrawlerTestCase extends TestCase
{
    protected int $now = 1_800_000_000;

    protected function clock(): \Closure
    {
        return fn (): int => $this->now;
    }

    protected function cache(): ArrayCache
    {
        return new ArrayCache($this->clock());
    }

    protected function verifier(?FakeDns $dns = null, ?FakeFetcher $fetcher = null, ?ArrayCache $cache = null, ?CrawlerCatalogue $catalogue = null): CrawlerVerifier
    {
        $catalogue ??= CrawlerCatalogue::default();
        $cache ??= $this->cache();
        $ranges = new IpRangeDirectory($catalogue, $fetcher, $cache, clock: $this->clock());

        return new CrawlerVerifier($catalogue, $dns, $ranges, $cache);
    }
}

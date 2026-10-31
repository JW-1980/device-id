<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Crawlers;

use DeviceId\Crawlers\ArrayCache;
use DeviceId\Crawlers\CrawlerCatalogue;
use DeviceId\Crawlers\CrawlerVerification;
use DeviceId\Crawlers\CrawlerVerifier;
use DeviceId\Crawlers\HostnameSuffix;
use DeviceId\Crawlers\IpRangeDirectory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

require_once __DIR__.'/CrawlerTestCase.php';

/**
 * Only Google's crawlers are "verified crawlers"; its user-triggered fetchers are not (skeptical
 * review H5). Google documents three classes (developers.google.com/crawling/docs/crawlers-fetchers/
 * verify-google-requests, retrieved 2026-10-31):
 *
 *  - common crawlers: `crawl-*.googlebot.com`, `geo-crawl-*.geo.googlebot.com`, common-crawlers.json;
 *  - special-case crawlers: `rate-limited-proxy-*.google.com`, special-crawlers.json;
 *  - user-triggered fetchers: `*.gae.googleusercontent.com` (Google Cloud CUSTOMER traffic),
 *    `google-proxy-*.google.com`, user-triggered-fetchers(-google).json, user-triggered-agents.json.
 */
final class UserTriggeredFetchersTest extends CrawlerTestCase
{
    private const GAE_IP = '107.178.192.5';

    private const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    /** Serves the App Engine prefix for every user-triggered feed URL and a crawler prefix for the crawler feeds. */
    private function googleFeeds(): FakeFetcher
    {
        $fetcher = new FakeFetcher;
        foreach (CrawlerCatalogue::default()->get('googlebot')?->rangeUrls ?? [] as $url) {
            $fetcher->bodies[$url] = str_contains($url, 'user-triggered')
                ? '{"prefixes":[{"ipv4Prefix":"107.178.192.0/24"}]}'
                : '{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"}]}';
        }

        return $fetcher;
    }

    #[Test]
    public function app_engine_customer_egress_with_a_googlebot_user_agent_is_not_a_verified_crawler(): void
    {
        $host = '107-178-192-5.gae.googleusercontent.com';
        $dns = new FakeDns([self::GAE_IP => $host], [$host => [self::GAE_IP]]);

        $verifier = $this->verifier($dns, $this->googleFeeds());
        $verdict = $verifier->verify(self::GAE_IP, (string) $verifier->claimFor(self::GOOGLEBOT_UA));

        self::assertFalse($verdict->isVerified(), 'App Engine egress is a Google Cloud customer, not Googlebot');
        self::assertTrue($verdict->isForged(), 'its PTR contradicts the claim and no crawler list contains it');
    }

    #[Test]
    public function the_crawler_identity_reads_only_the_crawler_lists_at_their_current_urls(): void
    {
        $urls = CrawlerCatalogue::default()->get('googlebot')?->rangeUrls;

        self::assertSame([
            'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
            'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
        ], $urls, 'the old /static/search/apis/ipranges/ URLs answer 301 and the fetchers refuse redirects');
    }

    /** @return iterable<string, array{string, string, bool}> */
    public static function googleHostnames(): iterable
    {
        yield 'common crawler' => ['66.249.66.1', 'crawl-66-249-66-1.googlebot.com', true];
        yield 'geo crawler' => ['35.247.243.240', 'geo-crawl-35-247-243-240.geo.googlebot.com', true];
        yield 'special-case crawler' => ['66.249.90.77', 'rate-limited-proxy-66-249-90-77.google.com', true];
        yield 'user-triggered Google proxy' => ['66.249.81.1', 'google-proxy-66-249-81-1.google.com', false];
        yield 'any other google.com name' => ['74.125.1.1', 'mail-wr1-f1.google.com', false];
        yield 'bare google.com' => ['142.250.1.1', 'google.com', false];
        yield 'special-case pattern one label too deep' => ['203.0.113.7', 'rate-limited-proxy-1.evil.google.com', false];
        yield 'other googlebot.com name' => ['203.0.113.8', 'something.googlebot.com', false];
    }

    #[Test]
    #[DataProvider('googleHostnames')]
    public function only_crawler_specific_google_hostnames_verify(string $ip, string $host, bool $verified): void
    {
        $dns = new FakeDns([$ip => $host], [$host => [$ip]]);

        $verdict = $this->verifier($dns)->verify($ip, 'googlebot');

        self::assertSame($verified, $verdict->isVerified(), $host);
        if (! $verified) {
            self::assertTrue($verdict->isForged(), $host.' forward-confirms but is not a crawler name');
        }
    }

    /** @return iterable<string, array{string}> */
    public static function userTriggeredAgents(): iterable
    {
        yield 'Feedfetcher' => ['FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)'];
        yield 'Google Read Aloud' => ['Mozilla/5.0 (Linux; Android 10) Chrome/120 Mobile Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)'];
        yield 'Google Site Verifier' => ['Mozilla/5.0 (compatible; Google-Site-Verification/1.0)'];
        yield 'Google Publisher Center' => ['GoogleProducer; (+https://developers.google.com/search/docs/crawling-indexing/google-producer)'];
        yield 'ChatGPT-User' => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot'];
        yield 'Claude-User' => ['Mozilla/5.0 (compatible; Claude-User/1.0; +Claude-User@anthropic.com)'];
        yield 'Perplexity-User' => ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)'];
    }

    #[Test]
    #[DataProvider('userTriggeredAgents')]
    public function user_triggered_fetchers_claim_no_crawler_identity(string $ua): void
    {
        self::assertNull(CrawlerCatalogue::default()->crawlerClaimFor($ua), 'a fetch a user triggered is ordinary traffic');
    }

    #[Test]
    public function no_default_crawler_reads_a_user_triggered_feed(): void
    {
        foreach (CrawlerCatalogue::default()->all() as $definition) {
            foreach ($definition->rangeUrls as $url) {
                self::assertDoesNotMatchRegularExpression('/user|chatgpt/i', $url, $definition->key);
            }
        }
    }

    #[Test]
    public function a_range_lookup_that_throws_is_undecided_never_verified(): void
    {
        $cache = new ArrayCache($this->clock());
        $cache->put('device-id:ranges:openai', ['fetched_at' => $this->now, 'prefixes' => ['20.0.0.0/24']], 3600);
        $cache->put('device-id:ranges:googlebot', ['fetched_at' => $this->now, 'prefixes' => ['66.249.64.0/19']], 3600);
        $catalogue = CrawlerCatalogue::default();
        // The clock is read when the cached list's age is checked: a throwing clock makes contains() throw.
        $ranges = new IpRangeDirectory($catalogue, null, $cache, clock: static fn (): int => throw new \RuntimeException('clock down'));
        $verifier = new CrawlerVerifier($catalogue, new FakeDns, $ranges, $cache);

        self::assertSame(CrawlerVerification::STATUS_UNVERIFIABLE, $verifier->verify('20.0.0.7', 'openai')->status);
        self::assertSame(CrawlerVerification::STATUS_UNVERIFIABLE, $verifier->verify('66.249.66.1', 'googlebot')->status);
    }

    /** @return iterable<string, array{string, bool}> */
    public static function patternHosts(): iterable
    {
        yield 'match' => ['rate-limited-proxy-66-249-90-77.google.com', true];
        yield 'trailing dot and case' => ['Rate-Limited-Proxy-1-2-3-4.Google.com.', true];
        yield 'empty wildcard' => ['rate-limited-proxy-.google.com', false];
        yield 'prefix glued' => ['xrate-limited-proxy-1.google.com', false];
        yield 'extra label' => ['rate-limited-proxy-1.evil.google.com', false];
        yield 'wrong domain' => ['rate-limited-proxy-1.google.com.evil.net', false];
        yield 'bare domain' => ['google.com', false];
    }

    #[Test]
    #[DataProvider('patternHosts')]
    public function a_wildcard_entry_matches_exactly_one_label_with_that_prefix(string $host, bool $expected): void
    {
        self::assertSame($expected, HostnameSuffix::matches($host, ['rate-limited-proxy-*.google.com']));
    }
}

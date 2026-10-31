<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Crawlers;

use DeviceId\Crawlers\CrawlerCatalogue;
use DeviceId\Crawlers\CrawlerDefinition;
use DeviceId\Crawlers\CrawlerVerification;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

require_once __DIR__.'/CrawlerTestCase.php';

final class CrawlerVerifierTest extends CrawlerTestCase
{
    private const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    private function genuineDns(): FakeDns
    {
        return new FakeDns(
            ['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com', '2001:4860:4801:10::1' => 'crawl-2001-4860-4801-10--1.googlebot.com'],
            ['crawl-66-249-66-1.googlebot.com' => ['66.249.66.1'], 'crawl-2001-4860-4801-10--1.googlebot.com' => ['2001:4860:4801:10:0:0:0:1']],
        );
    }

    #[Test]
    public function a_genuine_googlebot_is_verified_by_forward_confirmed_reverse_dns(): void
    {
        $v = $this->verifier($this->genuineDns())->verify('66.249.66.1', 'googlebot');

        self::assertTrue($v->isVerified());
        self::assertSame('crawl-66-249-66-1.googlebot.com', $v->hostname);
    }

    #[Test]
    public function ipv6_is_verified_and_spelling_does_not_matter(): void
    {
        $verifier = $this->verifier($this->genuineDns());

        self::assertTrue($verifier->verify('2001:4860:4801:10::1', 'googlebot')->isVerified());
        self::assertTrue($verifier->verify('2001:4860:4801:0010:0000:0000:0000:0001', 'googlebot')->isVerified());
    }

    #[Test]
    public function a_spoofed_user_agent_from_an_unrelated_address_is_forged(): void
    {
        $dns = new FakeDns(['203.0.113.9' => 'host9.example.net']);

        $v = $this->verifier($dns)->verify('203.0.113.9', 'googlebot');

        self::assertTrue($v->isForged());
        self::assertFalse($v->isVerified());
    }

    #[Test]
    public function reverse_dns_alone_without_forward_confirmation_is_forged(): void
    {
        // The attacker controls the PTR of their own address and points it at a Google name.
        $dns = new FakeDns(
            ['203.0.113.9' => 'crawl-1-2-3-4.googlebot.com'],
            ['crawl-1-2-3-4.googlebot.com' => ['66.249.66.1']],
        );

        self::assertTrue($this->verifier($dns)->verify('203.0.113.9', 'googlebot')->isForged());
    }

    #[Test]
    public function a_vendor_name_whose_forward_lookup_has_no_answer_is_undecided_not_verified(): void
    {
        $dns = new FakeDns(['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com'], []);

        $v = $this->verifier($dns)->verify('66.249.66.1', 'googlebot');

        self::assertSame(CrawlerVerification::STATUS_UNVERIFIABLE, $v->status);
    }

    /** @return iterable<string, array{string}> */
    public static function suffixAttacks(): iterable
    {
        yield 'prefix' => ['evil-googlebot.com'];
        yield 'domain inside another' => ['googlebot.com.evil.net'];
        yield 'glued label' => ['crawl.notgooglebot.com'];
        yield 'google.com lookalike' => ['crawl.fakegoogle.com'];
    }

    #[Test]
    #[DataProvider('suffixAttacks')]
    public function suffix_boundary_attacks_are_forged_even_when_they_forward_confirm(string $host): void
    {
        $dns = new FakeDns(['203.0.113.9' => $host], [$host => ['203.0.113.9']]);

        self::assertTrue($this->verifier($dns)->verify('203.0.113.9', 'googlebot')->isForged());
    }

    #[Test]
    public function dns_failure_fails_closed_to_unverified_never_verified(): void
    {
        $dns = $this->genuineDns();
        $dns->throws = true;
        $verifier = $this->verifier($dns);

        $v = $verifier->verify('66.249.66.1', 'googlebot');

        self::assertSame(CrawlerVerification::STATUS_UNVERIFIABLE, $v->status);
        self::assertFalse($v->isVerified());
        self::assertFalse($v->isForged(), 'a resolver outage is not evidence of forgery');
    }

    #[Test]
    public function no_ptr_answer_is_undecided(): void
    {
        self::assertSame(
            CrawlerVerification::STATUS_UNVERIFIABLE,
            $this->verifier(new FakeDns)->verify('66.249.66.1', 'googlebot')->status,
        );
    }

    #[Test]
    public function no_dns_adapter_at_all_fails_closed(): void
    {
        self::assertFalse($this->verifier(null)->verify('66.249.66.1', 'googlebot')->isVerified());
    }

    #[Test]
    public function an_invalid_address_and_an_unknown_crawler_are_never_verified(): void
    {
        $verifier = $this->verifier($this->genuineDns());

        self::assertFalse($verifier->verify('not-an-ip', 'googlebot')->isVerified());
        self::assertFalse($verifier->verify('66.249.66.1', 'nosuchbot')->isVerified());
        self::assertFalse($verifier->verify('66.249.66.1', 'uptimerobot')->isVerified(), 'a monitor is never a crawler');
    }

    #[Test]
    public function lookup_serves_the_cache_and_never_touches_dns(): void
    {
        $dns = $this->genuineDns();
        $verifier = $this->verifier($dns);

        $cold = $verifier->lookup('66.249.66.1', self::GOOGLEBOT_UA);
        self::assertSame(CrawlerVerification::STATUS_PENDING, $cold->status);
        self::assertSame(0, $dns->reverseCalls, 'the request path must not do DNS');

        $verifier->verifyAndCache('66.249.66.1', 'googlebot');
        $callsAfterVerify = $dns->reverseCalls;

        $warm = $verifier->lookup('66.249.66.1', self::GOOGLEBOT_UA);
        self::assertTrue($warm->isVerified());
        self::assertSame($callsAfterVerify, $dns->reverseCalls, 'cache hit: no further DNS');
    }

    #[Test]
    public function the_cache_is_per_address_and_per_crawler(): void
    {
        $verifier = $this->verifier($this->genuineDns());
        $verifier->verifyAndCache('66.249.66.1', 'googlebot');

        self::assertSame(CrawlerVerification::STATUS_PENDING, $verifier->lookup('66.249.66.2', self::GOOGLEBOT_UA)->status);
        self::assertSame(CrawlerVerification::STATUS_PENDING, $verifier->lookup('66.249.66.1', 'Bingbot/2.0')->status);
    }

    #[Test]
    public function a_failed_lookup_is_cached_short_and_retried_after_it_expires(): void
    {
        $dns = new FakeDns;
        $cache = $this->cache();
        $verifier = $this->verifier($dns, null, $cache);

        $verifier->verifyAndCache('66.249.66.1', 'googlebot');
        self::assertSame(CrawlerVerification::STATUS_UNVERIFIABLE, $verifier->lookup('66.249.66.1', self::GOOGLEBOT_UA)->status);

        $this->now += 301;
        self::assertSame(CrawlerVerification::STATUS_PENDING, $verifier->lookup('66.249.66.1', self::GOOGLEBOT_UA)->status, 'undecided verdicts expire after 5 minutes');
    }

    #[Test]
    public function one_caller_per_address_claims_the_background_resolution(): void
    {
        $verifier = $this->verifier($this->genuineDns());

        self::assertTrue($verifier->claimResolution('66.249.66.1', 'googlebot'));
        self::assertFalse($verifier->claimResolution('66.249.66.1', 'googlebot'));
        self::assertTrue($verifier->claimResolution('66.249.66.2', 'googlebot'));

        $verifier->verifyAndCache('66.249.66.1', 'googlebot');
        self::assertTrue($verifier->claimResolution('66.249.66.1', 'googlebot'), 'verification clears the marker');
    }

    #[Test]
    public function a_poisoned_cache_entry_for_another_crawler_is_a_miss(): void
    {
        $cache = $this->cache();
        $verifier = $this->verifier($this->genuineDns(), null, $cache);
        $verifier->verifyAndCache('66.249.66.1', 'bingbot');

        self::assertSame(CrawlerVerification::STATUS_PENDING, $verifier->lookup('66.249.66.1', self::GOOGLEBOT_UA)->status);
    }

    #[Test]
    public function a_vendor_with_no_method_is_undecided_never_verified(): void
    {
        $verifier = $this->verifier($this->genuineDns());

        // DuckDuckBot publishes no reverse DNS and no machine-readable list.
        $v = $verifier->lookup('66.249.66.1', 'Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)');

        self::assertSame(CrawlerVerification::STATUS_UNVERIFIABLE, $v->status);
        self::assertSame('duckduckbot', $v->crawler);
    }

    /** @return iterable<string, array{string, string}> */
    public static function claims(): iterable
    {
        yield 'Googlebot' => ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'googlebot'];
        yield 'Googlebot smartphone' => ['Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36 (compatible; Googlebot/2.1)', 'googlebot'];
        yield 'Google-InspectionTool' => ['Mozilla/5.0 (compatible; Google-InspectionTool/1.0)', 'googlebot'];
        yield 'GoogleOther' => ['GoogleOther', 'googlebot'];
        yield 'Storebot-Google' => ['Mozilla/5.0 (Linux; Android 8.0) Storebot-Google/1.0', 'googlebot'];
        yield 'AdsBot-Google' => ['AdsBot-Google (+http://www.google.com/adsbot.html)', 'googlebot'];
        yield 'Mediapartners-Google' => ['Mediapartners-Google', 'googlebot'];
        yield 'APIs-Google' => ['APIs-Google (+https://developers.google.com/webmasters/APIs-Google.html)', 'googlebot'];
        yield 'Bingbot' => ['Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 'bingbot'];
        yield 'Applebot' => ['Mozilla/5.0 (Macintosh) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)', 'applebot'];
        yield 'DuckDuckBot' => ['DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)', 'duckduckbot'];
        yield 'YandexBot' => ['Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)', 'yandex'];
        yield 'Baiduspider' => ['Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)', 'baiduspider'];
    }

    #[Test]
    #[DataProvider('claims')]
    public function every_default_crawler_is_recognised_by_its_user_agent(string $ua, string $expected): void
    {
        self::assertSame($expected, CrawlerCatalogue::default()->crawlerClaimFor($ua));
    }

    #[Test]
    public function ordinary_browsers_and_the_bare_words_bot_and_spider_claim_nothing(): void
    {
        $catalogue = CrawlerCatalogue::default();

        self::assertNull($catalogue->crawlerClaimFor('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36'));
        self::assertNull($catalogue->crawlerClaimFor('some-spider-bot crawler'));
        self::assertNull($catalogue->crawlerClaimFor(''));
        self::assertNull($catalogue->crawlerClaimFor(null));
    }

    #[Test]
    #[DataProvider('verifiedPairs')]
    public function yandex_baidu_bing_and_apple_verify_against_their_own_domains(string $crawler, string $host): void
    {
        $dns = new FakeDns(['198.51.100.7' => $host], [$host => ['198.51.100.7']]);
        $verifier = $this->verifier($dns);

        self::assertTrue($verifier->verify('198.51.100.7', $crawler)->isVerified());
        // ...and not against another vendor's domain.
        $other = $crawler === 'bingbot' ? 'applebot' : 'bingbot';
        self::assertTrue($verifier->verify('198.51.100.7', $other)->isForged());
    }

    /** @return iterable<string, array{string, string}> */
    public static function verifiedPairs(): iterable
    {
        yield 'bing' => ['bingbot', 'msnbot-157-55-39-1.search.msn.com'];
        yield 'apple' => ['applebot', '17-58-98-1.applebot.apple.com'];
        yield 'yandex' => ['yandex', 'spider-141-8-142-1.yandex.com'];
        yield 'baidu' => ['baiduspider', 'baiduspider-180-76-15-1.crawl.baidu.com'];
    }

    #[Test]
    public function googleusercontent_is_not_a_google_crawler_suffix(): void
    {
        // Every Compute Engine VM has a forward-confirming PTR under bc.googleusercontent.com.
        $host = '4.3.2.1.bc.googleusercontent.com';
        $dns = new FakeDns(['203.0.113.9' => $host], [$host => ['203.0.113.9']]);

        self::assertTrue($this->verifier($dns)->verify('203.0.113.9', 'googlebot')->isForged());
    }

    #[Test]
    public function a_published_list_verifies_and_a_list_without_the_address_contradicts_when_it_is_the_only_method(): void
    {
        $catalogue = CrawlerCatalogue::default()->with(new CrawlerDefinition('openai', 'OpenAI', CrawlerDefinition::KIND_CRAWLER, ['gptbot'], [], ['https://openai.example/gptbot.json']));
        $fetcher = new FakeFetcher(['https://openai.example/gptbot.json' => '{"prefixes":[{"ipv4Prefix":"20.0.0.0/24"},{"ipv6Prefix":"2001:db8:1::/48"}]}']);
        $verifier = $this->verifier(null, $fetcher, null, $catalogue);

        self::assertTrue($verifier->verify('20.0.0.77', 'openai')->isVerified());
        self::assertTrue($verifier->verify('2001:db8:1:5::1', 'openai')->isVerified());
        self::assertTrue($verifier->verify('20.0.1.1', 'openai')->isForged());

        $fetcher->down = true;
        $fresh = $this->verifier(null, $fetcher, null, $catalogue);
        self::assertSame(CrawlerVerification::STATUS_UNVERIFIABLE, $fresh->verify('20.0.0.77', 'openai')->status, 'no list: undecided, never verified, never forged');
    }

    #[Test]
    public function a_list_can_verify_a_dns_crawler_but_never_contradicts_it(): void
    {
        $url = 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json';
        $fetcher = new FakeFetcher([$url => '{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"}]}']);
        $verifier = $this->verifier(new FakeDns, $fetcher);

        self::assertTrue($verifier->verify('66.249.66.1', 'googlebot')->isVerified(), 'DNS had no answer, the list verifies');
        self::assertSame(CrawlerVerification::STATUS_UNVERIFIABLE, $verifier->verify('203.0.113.9', 'googlebot')->status, 'absence from a list is not a contradiction when DNS is the primary method');
    }
}

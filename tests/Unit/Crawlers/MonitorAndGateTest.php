<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Crawlers;

use NutriCompare\Fingerprint\Crawlers\ArrayCache;
use NutriCompare\Fingerprint\Crawlers\CrawlerCatalogue;
use NutriCompare\Fingerprint\Crawlers\CrawlerDefinition;
use NutriCompare\Fingerprint\Crawlers\CrawlerVerifier;
use NutriCompare\Fingerprint\Crawlers\IpRangeDirectory;
use NutriCompare\Fingerprint\Crawlers\OperatorAllowlist;
use NutriCompare\Fingerprint\Crawlers\TrafficGate;
use NutriCompare\Fingerprint\Support\Verdict;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

require_once __DIR__.'/CrawlerTestCase.php';

final class MonitorAndGateTest extends CrawlerTestCase
{
    private const UPTIMEROBOT_URL = 'https://cdn.uptimerobot.com/api/IPv4andIPv6.txt';

    private const UPTIMEROBOT_UA = 'Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)';

    private const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    private function gate(?FakeFetcher $fetcher = null, array $enabled = ['uptimerobot'], ?OperatorAllowlist $allowlist = null, ?FakeDns $dns = null, ?ArrayCache $cache = null): TrafficGate
    {
        $catalogue = CrawlerCatalogue::default();
        $cache ??= $this->cache();
        $ranges = new IpRangeDirectory($catalogue, $fetcher, $cache, clock: $this->clock());
        $verifier = new CrawlerVerifier($catalogue, $dns ?? new FakeDns, $ranges, $cache);

        return new TrafficGate($verifier, $allowlist ?? new OperatorAllowlist, $ranges, $enabled, $catalogue);
    }

    private function listBody(): string
    {
        return "# UptimeRobot\n216.144.248.16\n216.144.248.17, 69.162.124.0/24\n2607:ff68:107::/48\n";
    }

    #[Test]
    public function a_listed_address_is_a_verified_monitor_with_or_without_a_user_agent(): void
    {
        $gate = $this->gate(new FakeFetcher([self::UPTIMEROBOT_URL => $this->listBody()]));
        $gate->refreshMonitorLists();

        $withUa = $gate->classify('216.144.248.16', self::UPTIMEROBOT_UA);
        $ipOnly = $gate->classify('69.162.124.200', 'curl/8.0');

        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $withUa->decision);
        self::assertSame('uptimerobot', $withUa->matched);
        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $ipOnly->decision, 'IP alone is enough');
        self::assertTrue($ipOnly->isAllowed());
    }

    #[Test]
    public function ipv6_monitor_addresses_match(): void
    {
        $gate = $this->gate(new FakeFetcher([self::UPTIMEROBOT_URL => $this->listBody()]));
        $gate->refreshMonitorLists();

        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $gate->classify('2607:ff68:107:1::5', null)->decision);
        self::assertSame(Verdict::DECISION_SCORE, $gate->classify('2607:ff68:108::5', null)->decision);
    }

    #[Test]
    public function a_spoofed_monitor_user_agent_from_another_address_is_scored_normally_and_never_an_impersonation(): void
    {
        $gate = $this->gate(new FakeFetcher([self::UPTIMEROBOT_URL => $this->listBody()]));
        $gate->refreshMonitorLists();

        $c = $gate->classify('203.0.113.50', self::UPTIMEROBOT_UA);

        self::assertSame(Verdict::DECISION_SCORE, $c->decision, 'a User-Agent alone never allows');
        self::assertSame('uptimerobot', $c->unlistedMonitorClaim, 'reported for logging');
        self::assertNull($c->impersonationFinding(), 'monitors change addresses and lists lag: no signal that scores');
        self::assertFalse($c->verification->isForged());
    }

    #[Test]
    public function a_disabled_provider_allows_nothing_even_from_its_listed_address(): void
    {
        $fetcher = new FakeFetcher([self::UPTIMEROBOT_URL => $this->listBody()]);
        // Same cache, provider switched off.
        $cache = $this->cache();
        $on = $this->gate($fetcher, ['uptimerobot'], null, null, $cache);
        $on->refreshMonitorLists();
        $off = $this->gate($fetcher, [], null, null, $cache);

        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $on->classify('216.144.248.16', null)->decision);
        self::assertSame(Verdict::DECISION_SCORE, $off->classify('216.144.248.16', self::UPTIMEROBOT_UA)->decision);
        self::assertNull($off->classify('216.144.248.16', self::UPTIMEROBOT_UA)->unlistedMonitorClaim);
        self::assertSame([], $off->refreshMonitorLists());
        self::assertSame([], (new TrafficGate($this->verifier(), new OperatorAllowlist))->enabledMonitors(), 'default: no monitor enabled');
    }

    #[Test]
    public function a_failed_fetch_keeps_the_last_good_list_while_it_ages_past_freshness(): void
    {
        $fetcher = new FakeFetcher([self::UPTIMEROBOT_URL => $this->listBody()]);
        $gate = $this->gate($fetcher);
        $gate->refreshMonitorLists();

        $this->now += 90000; // 25 h: stale
        $fetcher->down = true;

        self::assertSame(['uptimerobot'], $gate->monitorsNeedingRefresh());
        self::assertSame(['uptimerobot' => false], $gate->refreshMonitorLists(), 'the refresh failed');
        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $gate->classify('216.144.248.16', null)->decision, 'the stale list still allows');

        // Retries are throttled instead of hammering a provider that is down.
        $calls = $fetcher->calls;
        $gate->refreshMonitorLists();
        self::assertSame($calls, $fetcher->calls);

        // When the provider is back the list is replaced.
        $this->now += 301;
        $fetcher->down = false;
        $fetcher->bodies[self::UPTIMEROBOT_URL] = "216.144.248.99\n";
        self::assertSame(['uptimerobot' => true], $gate->refreshMonitorLists());
        self::assertSame(Verdict::DECISION_SCORE, $gate->classify('216.144.248.16', null)->decision);
        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $gate->classify('216.144.248.99', null)->decision);
    }

    #[Test]
    public function with_no_list_at_all_it_fails_closed(): void
    {
        $fetcher = new FakeFetcher;
        $fetcher->down = true;
        $gate = $this->gate($fetcher);

        self::assertSame(['uptimerobot' => false], $gate->refreshMonitorLists());
        self::assertSame(Verdict::DECISION_SCORE, $gate->classify('216.144.248.16', self::UPTIMEROBOT_UA)->decision);
    }

    #[Test]
    public function an_empty_or_garbage_2xx_body_does_not_replace_a_good_list(): void
    {
        $fetcher = new FakeFetcher([self::UPTIMEROBOT_URL => $this->listBody()]);
        $gate = $this->gate($fetcher);
        $gate->refreshMonitorLists();

        $this->now += 90000;
        $fetcher->bodies[self::UPTIMEROBOT_URL] = '<html>Service unavailable</html>';
        $gate->refreshMonitorLists();

        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $gate->classify('216.144.248.16', null)->decision);
    }

    #[Test]
    public function a_list_that_contains_a_slash_zero_cannot_allow_everything(): void
    {
        $gate = $this->gate(new FakeFetcher([self::UPTIMEROBOT_URL => "0.0.0.0/0\n::/0\n216.144.248.16\n"]));
        $gate->refreshMonitorLists();

        self::assertSame(Verdict::DECISION_SCORE, $gate->classify('8.8.8.8', null)->decision);
        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $gate->classify('216.144.248.16', null)->decision);
    }

    #[Test]
    public function a_config_only_provider_allows_nothing_from_the_catalogue_alone(): void
    {
        $gate = $this->gate(new FakeFetcher, ['site24x7', 'freshping']);

        self::assertSame(['site24x7' => false, 'freshping' => false], $gate->refreshMonitorLists());
        self::assertSame(Verdict::DECISION_SCORE, $gate->classify('203.0.113.9', 'Site24x7')->decision);
        // The operator's own CIDRs are the way to allow it.
        $listed = $this->gate(null, ['site24x7'], new OperatorAllowlist(['203.0.113.0/28']));
        self::assertSame(Verdict::ALLOW_LISTED, $listed->classify('203.0.113.9', 'Site24x7')->decision);
    }

    #[Test]
    public function datadog_takes_only_the_synthetics_paths_of_its_document(): void
    {
        $json = json_encode([
            'agents' => ['prefixes_ipv4' => ['10.1.0.0/16']],
            'synthetics' => ['prefixes_ipv4' => ['10.2.0.0/16'], 'prefixes_ipv6' => ['2001:db8:2::/48'], 'prefixes_ipv4_by_location' => ['x' => ['10.9.0.0/16']]],
        ], JSON_THROW_ON_ERROR);
        $gate = $this->gate(new FakeFetcher(['https://ip-ranges.datadoghq.com/' => $json]), ['datadog_synthetics']);
        $gate->refreshMonitorLists();

        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $gate->classify('10.2.3.4', null)->decision);
        self::assertSame(Verdict::ALLOW_VERIFIED_MONITOR, $gate->classify('2001:db8:2::9', null)->decision);
        self::assertSame(Verdict::DECISION_SCORE, $gate->classify('10.1.3.4', null)->decision, 'the agents range is not a synthetics range');
    }

    /** @return iterable<string, array{string}> */
    public static function monitorKeys(): iterable
    {
        foreach (['uptimerobot', 'pingdom', 'betterstack', 'statuscake', 'ohdear', 'site24x7', 'freshping', 'checkly', 'datadog_synthetics', 'hetrixtools'] as $key) {
            yield $key => [$key];
        }
    }

    #[Test]
    #[DataProvider('monitorKeys')]
    public function every_required_monitor_is_in_the_catalogue_and_urls_are_https_only(string $key): void
    {
        $definition = CrawlerCatalogue::default()->get($key);

        self::assertNotNull($definition);
        self::assertTrue($definition->isMonitor());
        self::assertSame([], $definition->rdnsSuffixes, 'monitors are provable by list only');
        foreach ($definition->rangeUrls as $url) {
            self::assertStringStartsWith('https://', $url);
        }
    }

    #[Test]
    public function a_definition_drops_non_https_feed_urls(): void
    {
        $d = CrawlerDefinition::fromArray('x', ['kind' => 'monitor', 'ip_ranges' => ['http://insecure.example/ips.txt', 'https://ok.example/ips.txt']]);

        self::assertSame(['https://ok.example/ips.txt'], $d->rangeUrls);
    }

    #[Test]
    public function the_operator_allowlist_wins_and_is_marked_listed(): void
    {
        $gate = $this->gate(null, [], new OperatorAllowlist(['203.0.113.0/24'], ['dk-ops']), new FakeDns);

        $byIp = $gate->classify('203.0.113.5', 'curl/8');
        $byKey = $gate->classify('198.51.100.1', 'curl/8', 'dk-ops');

        self::assertSame(Verdict::ALLOW_LISTED, $byIp->decision);
        self::assertSame('ip', $byIp->listedBy);
        self::assertSame('203.0.113.0/24', $byIp->matched);
        self::assertSame(Verdict::ALLOW_LISTED, $byKey->decision);
        self::assertSame('device_key', $byKey->listedBy);
        self::assertSame(Verdict::DECISION_SCORE, $gate->classify('198.51.100.1', 'curl/8', 'other')->decision);
    }

    #[Test]
    public function a_verified_crawler_is_allowed_a_forged_one_is_scored_with_an_impersonation_finding(): void
    {
        $dns = new FakeDns(
            ['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com', '203.0.113.9' => 'host9.example.net'],
            ['crawl-66-249-66-1.googlebot.com' => ['66.249.66.1']],
        );
        $cache = $this->cache();
        $gate = $this->gate(null, [], null, $dns, $cache);

        // Cold: pending, scored normally, no finding yet.
        $cold = $gate->classify('66.249.66.1', self::GOOGLEBOT_UA);
        self::assertSame(Verdict::DECISION_SCORE, $cold->decision);
        self::assertNull($cold->impersonationFinding());
        self::assertFalse($cold->fingerprintExpected(), 'a claimed crawler has no fingerprint to expect');

        $verifier = new CrawlerVerifier(CrawlerCatalogue::default(), $dns, null, $cache);
        $verifier->verifyAndCache('66.249.66.1', 'googlebot');
        $verifier->verifyAndCache('203.0.113.9', 'googlebot');

        $genuine = $gate->classify('66.249.66.1', self::GOOGLEBOT_UA);
        $spoof = $gate->classify('203.0.113.9', self::GOOGLEBOT_UA);

        self::assertSame(Verdict::ALLOW_VERIFIED_CRAWLER, $genuine->decision);
        self::assertSame(Verdict::DECISION_SCORE, $spoof->decision);
        self::assertSame('crawler_impersonation', $spoof->impersonationFinding()?->code);
        self::assertTrue($spoof->impersonationFinding()?->isHard());
        self::assertTrue($gate->classify('198.51.100.1', 'Mozilla/5.0 Chrome/120')->fingerprintExpected());
    }

    #[Test]
    public function an_allowlisted_address_claiming_googlebot_is_still_allowed(): void
    {
        $gate = $this->gate(null, [], new OperatorAllowlist(['203.0.113.9']), new FakeDns(['203.0.113.9' => 'host9.example.net']));

        self::assertSame(Verdict::ALLOW_LISTED, $gate->classify('203.0.113.9', self::GOOGLEBOT_UA)->decision);
    }

    #[Test]
    public function the_allowance_marker_forces_the_pass_band_and_keeps_analysis_only_on_request(): void
    {
        $scored = new Verdict(Verdict::BAND_CHALLENGE, 68, ['x'], [['code' => 'x', 'detail' => 'd', 'weight' => 45]]);
        $gate = $this->gate(null, [], new OperatorAllowlist(['203.0.113.9']));
        $allowed = $gate->classify('203.0.113.9', null);

        $plain = $allowed->applyTo($scored);
        $kept = $allowed->applyTo($scored, true);
        $notAllowed = $gate->classify('198.51.100.1', null)->applyTo($scored);

        self::assertSame(Verdict::BAND_PASS, $plain->band);
        self::assertSame(Verdict::ALLOW_LISTED, $plain->decision());
        self::assertSame(0, $plain->score);
        self::assertSame([], $plain->disagreements);

        self::assertSame(Verdict::BAND_PASS, $kept->band, 'analysis kept, but never challenged or blocked');
        self::assertSame(68, $kept->score);
        self::assertSame(['x'], $kept->reasons);
        self::assertSame('ALLOW_LISTED', $kept->toArray()['allowance']);

        self::assertSame($scored, $notAllowed);
        self::assertSame(Verdict::DECISION_SCORE, $scored->decision());
        self::assertArrayNotHasKey('allowance', $scored->toArray());
    }

    #[Test]
    public function broken_adapters_fail_closed(): void
    {
        $dns = new FakeDns(['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com'], ['crawl-66-249-66-1.googlebot.com' => ['66.249.66.1']]);
        $dns->throws = true;
        $gate = $this->gate(null, [], null, $dns);

        self::assertFalse($gate->classify('66.249.66.1', self::GOOGLEBOT_UA)->isAllowed());
        self::assertFalse($gate->classify('not-an-ip', self::GOOGLEBOT_UA)->isAllowed());
    }
}

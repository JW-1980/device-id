<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Crawlers\ArrayCache;
use DeviceId\Crawlers\RangeFetcher;
use DeviceId\Reputation\FeedCatalogue;
use DeviceId\Reputation\FeedDefinition;
use DeviceId\Reputation\FeedParser;
use DeviceId\Reputation\IpReputation;
use DeviceId\Reputation\PrefixSet;
use DeviceId\Reputation\ReputationResult;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ReputationTest extends TestCase
{
    private int $now = 1_000_000;

    private function feed(string $key, string $format, string $category, string $licence = FeedDefinition::LICENCE_PERMITTED_WITH_NOTICE, int $minimum = 3600, string $attribution = ''): FeedDefinition
    {
        return new FeedDefinition($key, $key, 'https://feeds.test/'.$key, $format, $category, ['status' => $licence, 'note' => '', 'source' => '', 'checked_on' => '2026-10-31'], $attribution, $minimum);
    }

    /**
     * @param  array<string, string|null>  $bodies  url => body
     */
    private function fetcher(array &$bodies, int &$calls = 0): RangeFetcher
    {
        return new class($bodies, $calls) implements RangeFetcher
        {
            /** @param array<string, string|null> $bodies */
            public function __construct(private array &$bodies, private int &$calls) {}

            public function fetch(string $url): ?string
            {
                $this->calls++;

                return $this->bodies[$url] ?? null;
            }
        };
    }

    #[Test]
    public function every_default_feed_has_a_dated_licence_finding_and_the_incompatible_ones_are_absent(): void
    {
        $feeds = FeedCatalogue::defaults();

        $this->assertSame([], array_values(array_filter(array_keys($feeds), static fn (string $k): bool => str_contains($k, 'spamhaus') || str_contains($k, 'drop'))), 'Spamhaus needs credit and its name may not appear in commercial materials');
        $this->assertSame([], array_filter($feeds, static fn (FeedDefinition $f): bool => $f->category === FeedDefinition::CATEGORY_ABUSE_LIST), 'no shipped list: the abuse signal is first-party');
        $this->assertArrayNotHasKey('firehol_level1', $feeds, 'FireHOL level1 carries DShield, a NonCommercial licence');
        $this->assertArrayNotHasKey('dshield', $feeds);
        foreach ($feeds as $feed) {
            $this->assertNotSame(FeedDefinition::LICENCE_NOT_COMPATIBLE, $feed->licence['status']);
            $this->assertSame('2026-10-31', $feed->licence['checked_on']);
            $this->assertStringStartsWith('https://', $feed->url);
        }
        foreach ($feeds as $feed) {
            $this->assertSame('', $feed->attribution, $feed->key.' must not need a public credit');
            $this->assertNotSame(FeedDefinition::LICENCE_PUBLIC_CREDIT_REQUIRED, $feed->licence['status']);
            $this->assertStringNotContainsStringIgnoringCase('spamhaus', json_encode($feed));
        }
        $this->assertSame(FeedDefinition::LICENCE_PERMITTED, $feeds['tor_exit']->licence['status'], 'CollecTor tordnsel is CC0 per Tor Metrics');
        $this->assertSame(FeedDefinition::FORMAT_TORDNSEL_DIRECTORY, $feeds['tor_exit']->format);
    }

    #[Test]
    public function the_parsers_read_each_published_format(): void
    {
        $this->assertSame(['1.10.16.0/20', '1.19.0.0/16'], FeedParser::parse(FeedDefinition::FORMAT_NDJSON_CIDR, "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL1\",\"rir\":\"apnic\"}\n{\"cidr\":\"1.19.0.0/16\"}\n{\"type\":\"metadata\"}\n"));
        $this->assertSame(['171.25.193.25/32', '2001:db8::1/128'], FeedParser::parse(FeedDefinition::FORMAT_IP_LINES, "171.25.193.25\n# comment\n2001:db8::1\n"));
        $this->assertSame(['3.4.12.4/32', '2600:1f00::/24'], FeedParser::parse(FeedDefinition::FORMAT_AWS, '{"prefixes":[{"ip_prefix":"3.4.12.4/32"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/24"}]}'));
        $this->assertSame(['34.1.208.0/20', '2600:1900::/35'], FeedParser::parse(FeedDefinition::FORMAT_GCP, '{"prefixes":[{"ipv4Prefix":"34.1.208.0/20"},{"ipv6Prefix":"2600:1900::/35"}]}'));
        $this->assertSame(['147.154.0.0/18'], FeedParser::parse(FeedDefinition::FORMAT_ORACLE, '{"regions":[{"region":"x","cidrs":[{"cidr":"147.154.0.0/18","tags":["OCI"]}]}]}'));
        $this->assertSame(['5.101.96.0/21'], FeedParser::parse(FeedDefinition::FORMAT_CSV_FIRST_COLUMN, "5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH\n"));
    }

    #[Test]
    public function a_body_that_parses_to_nothing_is_a_failure_and_a_zero_prefix_is_refused(): void
    {
        $this->assertNull(FeedParser::parse(FeedDefinition::FORMAT_IP_LINES, "garbage\n"));
        $this->assertNull(FeedParser::parse(FeedDefinition::FORMAT_NDJSON_CIDR, '{"cidr":"0.0.0.0/0"}'), 'a /0 would list the whole internet');
        $this->assertNull(FeedParser::parse(FeedDefinition::FORMAT_AWS, 'not json'));
    }

    #[Test]
    public function the_prefix_set_matches_by_network_in_both_families(): void
    {
        $set = new PrefixSet(['10.0.0.0/8', '192.0.2.128/25', '2001:db8::/32', '203.0.113.7/32']);

        $this->assertTrue($set->contains('10.200.1.1'));
        $this->assertTrue($set->contains('192.0.2.200'));
        $this->assertFalse($set->contains('192.0.2.5'));
        $this->assertTrue($set->contains('2001:db8:ffff::1'));
        $this->assertFalse($set->contains('2001:db9::1'));
        $this->assertTrue($set->contains('203.0.113.7'));
        $this->assertFalse($set->contains('203.0.113.8'));
        $this->assertFalse($set->contains('not an ip'));
        $this->assertTrue($set->contains('::ffff:10.1.2.3'), 'an IPv4-mapped IPv6 client is an IPv4 client');
    }

    #[Test]
    public function a_refreshed_feed_is_looked_up_with_its_category_and_source(): void
    {
        $bodies = ['https://feeds.test/drop' => '{"cidr":"198.51.100.0/24"}', 'https://feeds.test/aws' => '{"prefixes":[{"ip_prefix":"203.0.113.0/24"}]}'];
        $reputation = new IpReputation(
            ['drop' => $this->feed('drop', FeedDefinition::FORMAT_NDJSON_CIDR, FeedDefinition::CATEGORY_ABUSE_LIST), 'aws' => $this->feed('aws', FeedDefinition::FORMAT_AWS, FeedDefinition::CATEGORY_DATACENTER, FeedDefinition::LICENCE_PERMITTED)],
            $this->fetcher($bodies), new ArrayCache(fn (): int => $this->now), clock: fn (): int => $this->now,
        );

        $this->assertSame(['drop' => 'refreshed', 'aws' => 'refreshed'], $reputation->refreshStale());

        $listed = $reputation->lookup('198.51.100.9');
        $this->assertTrue($listed->isAbuseListed());
        $this->assertFalse($listed->isDatacenter());
        $this->assertSame(['drop'], $listed->sources);
        $this->assertSame([], $listed->attribution);
        $this->assertSame(ReputationResult::STATE_OK, $listed->state);
        $this->assertSame(['rep_abuse_listed' => 1.0], $listed->features());
        $this->assertTrue($reputation->lookup('203.0.113.1')->isDatacenter());

        $clean = $reputation->lookup('192.0.2.1');
        $this->assertSame([], $clean->categories);
        $this->assertSame([], $clean->features());
        $this->assertTrue($clean->ruleInput()['known']);
        $this->assertTrue($clean->ruleInput()['complete']);
    }

    #[Test]
    public function an_unaccepted_unverified_licence_is_never_loaded_and_makes_the_answer_partial(): void
    {
        $bodies = ['https://feeds.test/aws' => '{"prefixes":[{"ip_prefix":"203.0.113.0/24"}]}', 'https://feeds.test/drop' => '{"cidr":"198.51.100.0/24"}'];
        $calls = 0;
        $feeds = ['aws' => $this->feed('aws', FeedDefinition::FORMAT_AWS, FeedDefinition::CATEGORY_DATACENTER, FeedDefinition::LICENCE_UNVERIFIED), 'drop' => $this->feed('drop', FeedDefinition::FORMAT_NDJSON_CIDR, FeedDefinition::CATEGORY_ABUSE_LIST)];
        $cache = new ArrayCache(fn (): int => $this->now);

        $strict = new IpReputation($feeds, $this->fetcher($bodies, $calls), $cache, clock: fn (): int => $this->now);
        $strict->refreshStale();

        $this->assertSame(1, $calls, 'the unverified feed was not even fetched');
        $result = $strict->lookup('203.0.113.1');
        $this->assertFalse($result->isDatacenter());
        $this->assertSame(ReputationResult::STATE_PARTIAL, $result->state);
        $this->assertContains('aws', $result->unusableFeeds);
        $this->assertFalse($result->ruleInput()['complete'], 'silence from an unloaded feed is not a clean answer');

        $accepting = new IpReputation($feeds, $this->fetcher($bodies, $calls), new ArrayCache(fn (): int => $this->now), acceptUnverified: ['aws'], clock: fn (): int => $this->now);
        $accepting->refreshStale();
        $this->assertTrue($accepting->lookup('203.0.113.1')->isDatacenter());
    }

    #[Test]
    public function a_not_compatible_licence_is_never_loaded_even_when_accepted(): void
    {
        $bodies = ['https://feeds.test/nc' => "198.51.100.1\n"];
        $feeds = ['nc' => $this->feed('nc', FeedDefinition::FORMAT_IP_LINES, FeedDefinition::CATEGORY_ABUSE_LIST, FeedDefinition::LICENCE_NOT_COMPATIBLE)];
        $reputation = new IpReputation($feeds, $this->fetcher($bodies), new ArrayCache(fn (): int => $this->now), acceptUnverified: ['nc'], clock: fn (): int => $this->now);

        $this->assertSame([], $reputation->enabledFeeds());
        $this->assertSame(ReputationResult::STATE_UNAVAILABLE, $reputation->lookup('198.51.100.1')->state);
    }

    #[Test]
    public function a_list_older_than_the_maximum_age_is_ignored_not_used(): void
    {
        $bodies = ['https://feeds.test/drop' => '{"cidr":"198.51.100.0/24"}'];
        $reputation = new IpReputation(['drop' => $this->feed('drop', FeedDefinition::FORMAT_NDJSON_CIDR, FeedDefinition::CATEGORY_ABUSE_LIST)], $this->fetcher($bodies), new ArrayCache(fn (): int => $this->now), clock: fn (): int => $this->now);
        $reputation->refresh('drop');
        $this->assertTrue($reputation->lookup('198.51.100.9')->isAbuseListed());

        $this->now += 3 * 86400;
        $this->assertTrue($reputation->lookup('198.51.100.9')->isAbuseListed(), 'stale but inside the maximum age: still used');

        $this->now += 5 * 86400;
        $old = $reputation->lookup('198.51.100.9');
        $this->assertFalse($old->isAbuseListed(), 'a list that stopped updating is no evidence about today');
        $this->assertSame(ReputationResult::STATE_UNAVAILABLE, $old->state);
        $this->assertFalse($old->ruleInput()['known']);
    }

    #[Test]
    public function a_failed_refresh_keeps_the_last_good_list_and_respects_the_minimum_interval(): void
    {
        $bodies = ['https://feeds.test/drop' => '{"cidr":"198.51.100.0/24"}'];
        $calls = 0;
        $reputation = new IpReputation(['drop' => $this->feed('drop', FeedDefinition::FORMAT_NDJSON_CIDR, FeedDefinition::CATEGORY_ABUSE_LIST, minimum: 3600)], $this->fetcher($bodies, $calls), new ArrayCache(fn (): int => $this->now), clock: fn (): int => $this->now);

        $this->assertTrue($reputation->refresh('drop'));
        $this->assertFalse($reputation->refresh('drop'), 'inside the minimum interval: no second download');
        $this->assertSame(1, $calls);

        $this->now += 4000;
        $bodies['https://feeds.test/drop'] = null; // the publisher is down
        $this->assertFalse($reputation->refresh('drop'));
        $this->assertTrue($reputation->lookup('198.51.100.9')->isAbuseListed(), 'the last good list survives an outage');
        $this->now += 4000;
        $bodies['https://feeds.test/drop'] = 'garbage';
        $this->assertFalse($reputation->refresh('drop'), 'a body that parses to nothing replaces nothing');
        $this->assertTrue($reputation->lookup('198.51.100.9')->isAbuseListed());
    }

    #[Test]
    public function without_a_fetcher_or_a_cache_nothing_is_known_and_nothing_is_claimed(): void
    {
        $reputation = new IpReputation(['drop' => $this->feed('drop', FeedDefinition::FORMAT_NDJSON_CIDR, FeedDefinition::CATEGORY_ABUSE_LIST)]);

        $this->assertFalse($reputation->refresh('drop'));
        $this->assertSame(ReputationResult::STATE_UNAVAILABLE, $reputation->lookup('198.51.100.9')->state);
    }

    #[Test]
    public function a_reputation_result_carries_no_score_band_or_weight_so_an_address_cannot_block(): void
    {
        $properties = array_map(static fn (\ReflectionProperty $p): string => $p->getName(), (new \ReflectionClass(ReputationResult::class))->getProperties());
        sort($properties);

        $this->assertSame(['attribution', 'categories', 'sources', 'state', 'unusableFeeds'], $properties);
        $this->assertFalse(method_exists(ReputationResult::class, 'band'));
        $this->assertFalse(method_exists(ReputationResult::class, 'weight'));
    }

    #[Test]
    public function the_tor_exit_list_is_read_from_the_newest_file_of_the_collector_directory(): void
    {
        $index = '<a href="?C=N;O=D">Name</a><a href="2026-10-27-10-12-11">x</a><a href="2026-10-27-12-11-47">x</a><a href="2026-10-27-11-11-47">x</a>';
        $list = "@type tordnsel 1.0\nDownloaded 2026-10-27 12:11:47\nExitNode AAAA\nPublished 2026-10-27 08:00:00\nLastStatus 2026-10-27 11:00:00\nExitAddress 171.25.193.25 2026-10-27 11:30:00\nExitNode BBBB\nExitAddress 2001:db8::7 2026-10-27 11:31:00\n";
        $this->assertSame('2026-10-27-12-11-47', FeedParser::newestExitListName($index));
        $this->assertNull(FeedParser::newestExitListName('<html>nothing here</html>'));
        $this->assertSame(['171.25.193.25/32', '2001:db8::7/128'], FeedParser::parse(FeedDefinition::FORMAT_TORDNSEL_DIRECTORY, $list));

        $calls = 0;
        $bodies = ['https://collector.test/exit-lists/' => $index, 'https://collector.test/exit-lists/2026-10-27-12-11-47' => $list];
        $feed = new FeedDefinition('tor', 'tor', 'https://collector.test/exit-lists/', FeedDefinition::FORMAT_TORDNSEL_DIRECTORY, FeedDefinition::CATEGORY_TOR_EXIT, ['status' => FeedDefinition::LICENCE_PERMITTED, 'note' => '', 'source' => '', 'checked_on' => '2026-10-31']);
        $reputation = new IpReputation(['tor' => $feed], $this->fetcher($bodies, $calls), new ArrayCache(fn (): int => $this->now), clock: fn (): int => $this->now);

        $this->assertTrue($reputation->refresh('tor'));
        $this->assertSame(2, $calls, 'the index, then the newest file');
        $this->assertTrue($reputation->lookup('171.25.193.25')->isTorExit());
        $this->assertFalse($reputation->lookup('171.25.193.26')->isTorExit());

        $this->now += 7200;
        $bodies = ['https://collector.test/exit-lists/' => $index];
        $this->assertFalse($reputation->refresh('tor'), 'the file missing is a failed refresh, never an empty list');
        $this->assertTrue($reputation->lookup('171.25.193.25')->isTorExit(), 'the last good list survives');
    }

    #[Test]
    public function a_feed_that_carries_a_credit_text_is_never_loaded(): void
    {
        $bodies = ['https://feeds.test/credit' => '{"cidr":"198.51.100.0/24"}'];
        $calls = 0;
        $reputation = new IpReputation(['credit' => $this->feed('credit', FeedDefinition::FORMAT_NDJSON_CIDR, FeedDefinition::CATEGORY_ABUSE_LIST, FeedDefinition::LICENCE_PERMITTED, attribution: 'Data by Somebody')], $this->fetcher($bodies, $calls), new ArrayCache(fn (): int => $this->now), clock: fn (): int => $this->now);

        $this->assertSame([], $reputation->enabledFeeds());
        $this->assertFalse($reputation->refresh('credit'));
        $this->assertSame(0, $calls);
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Network;

use DeviceId\Crawlers\ArrayCache;
use DeviceId\Crawlers\RangeFetcher;
use DeviceId\Network\AsnClassifier;
use DeviceId\Network\NetworkDatabase;
use DeviceId\Network\NetworkFacts;
use DeviceId\Network\NetworkFeed;
use DeviceId\Network\NetworkFeedCatalogue;
use DeviceId\Network\RangeTable;
use DeviceId\Reputation\ReputationResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The local IP data: parsing the real file formats (fixtures are real lines of the DB-IP,
 * IPtoASN and bad-asn-list downloads of 2026-10-31), shard boundaries, the freshness and
 * licence rules, and the guarantee that a lookup never touches the network.
 */
final class NetworkDatabaseTest extends TestCase
{
    private int $now = 1_793_000_000; // 2026-10-26

    private int $calls = 0;

    /** @var array<string, string|null> */
    private array $bodies = [];

    private function fixture(string $name): string
    {
        $text = file_get_contents(__DIR__.'/../../Fixtures/network/'.$name);
        self::assertIsString($text);

        return $text;
    }

    private function fetcher(): RangeFetcher
    {
        return new class($this->bodies, $this->calls) implements RangeFetcher
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

    private function database(?ArrayCache $cache = null, array $feeds = [], array $accept = []): NetworkDatabase
    {
        $clock = fn (): int => $this->now;

        return new NetworkDatabase($feeds === [] ? NetworkFeedCatalogue::defaults() : $feeds, $this->fetcher(), $cache ?? new ArrayCache($clock), $accept, $clock, 10);
    }

    private function loadFixtures(): NetworkDatabase
    {
        $this->bodies = [
            'https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz' => gzencode($this->fixture('dbip-country-lite-sample.csv')),
            'https://iptoasn.com/data/ip2asn-combined.tsv.gz' => gzencode($this->fixture('ip2asn-sample.tsv')),
            'https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv' => $this->fixture('bad-asn-list-sample.csv'),
        ];
        $database = $this->database();
        $this->assertSame(['dbip_country' => 'refreshed', 'iptoasn' => 'refreshed', 'bad_asn_list' => 'refreshed'], $database->refreshStale());

        return $database;
    }

    #[Test]
    public function the_real_file_formats_load_and_answer_country_asn_and_category(): void
    {
        $database = $this->loadFixtures();

        $google = $database->lookup('8.8.8.8');
        $this->assertSame(NetworkFacts::STATE_OK, $google->state);
        $this->assertSame('US', $google->country);
        $this->assertSame(15169, $google->asn);
        $this->assertSame(NetworkFacts::CATEGORY_HOSTING, $google->asnCategory, 'GOOGLE is in the hosting list');

        $vpn = $database->lookup('5.199.4.10');
        $this->assertSame('GB', $vpn->country);
        $this->assertSame(218799, $vpn->asn);
        $this->assertTrue($vpn->isVpn(), 'LITE-VPN-AS names itself a VPN');
        $this->assertFalse($vpn->isHosting(), 'one address never pays for both');

        $home = $database->lookup('81.30.1.1');
        $this->assertSame('IT', $home->country);
        $this->assertNull($home->asnCategory, 'no flag is not "residential", it is just no flag');
        $this->assertFalse($home->isHosting() || $home->isVpn());

        $this->assertSame('DE', $database->lookup('2a00:1450:4001:81b::200e')->country, 'IPv6 shards');
        $this->assertSame('US', $database->lookup('185.220.101.200')->country, 'a range split inside a /24');
        $this->assertSame('DE', $database->lookup('185.220.101.5')->country);
    }

    #[Test]
    public function an_address_outside_every_range_and_a_malformed_one_have_no_country(): void
    {
        $database = $this->loadFixtures();

        $private = $database->lookup('192.168.1.1');
        $this->assertNull($private->country);
        $this->assertNull($private->asn);
        $this->assertSame(NetworkFacts::STATE_OK, $private->state, 'the datasets answered; there was just no range');

        $bad = $database->lookup('not an address');
        $this->assertSame(NetworkFacts::STATE_UNAVAILABLE, $bad->state);
        $this->assertNull($bad->country);
        $this->assertSame('IT', $database->lookup('::ffff:81.30.1.1')->country, 'an IPv4-mapped address is looked up as IPv4');
    }

    #[Test]
    public function a_lookup_never_calls_the_fetcher(): void
    {
        $database = $this->loadFixtures();
        $before = $this->calls;

        for ($i = 0; $i < 50; $i++) {
            $database->lookup('8.8.8.'.$i);
        }

        $this->assertSame($before, $this->calls, 'the request path reads the cache only');
        $cold = $this->database(new ArrayCache);
        $this->assertSame(NetworkFacts::STATE_UNAVAILABLE, $cold->lookup('8.8.8.8')->state, 'nothing fetched means no answer, and no fetch to get one');
        $this->assertSame($before, $this->calls);
    }

    #[Test]
    public function a_dataset_past_its_maximum_age_is_ignored_and_never_read_as_domestic(): void
    {
        $database = $this->loadFixtures();

        $this->now += 20 * 86400; // the country file allows 75 days, the ASN file 14
        $partial = $database->lookup('8.8.8.8');
        $this->assertSame(NetworkFacts::STATE_PARTIAL, $partial->state);
        $this->assertSame('US', $partial->country);
        $this->assertNull($partial->asn, 'a stale ASN file is not consulted');
        $this->assertNull($partial->asnCategory);
        $this->assertContains('iptoasn', $partial->unusable);

        $this->now += 70 * 86400;
        $stale = $database->lookup('8.8.8.8');
        $this->assertSame(NetworkFacts::STATE_PARTIAL, $stale->state, 'only the one-year hosting list is still usable');
        $this->assertNull($stale->country, 'an old file says nothing, not "domestic"');
        $this->assertContains('dbip_country', $stale->unusable);
        $this->assertContains('iptoasn', $stale->unusable);
    }

    #[Test]
    public function a_failed_or_truncated_refresh_keeps_the_previous_version(): void
    {
        $clock = fn (): int => $this->now;
        $cache = new ArrayCache($clock);
        $this->bodies = ['https://iptoasn.com/data/ip2asn-combined.tsv.gz' => gzencode($this->fixture('ip2asn-sample.tsv'))];
        $database = $this->database($cache, ['iptoasn' => NetworkFeedCatalogue::defaults()['iptoasn']]);
        $this->assertTrue($database->refresh('iptoasn'));
        $this->assertSame(15169, $database->lookup('8.8.8.8')->asn);

        $this->now += 2 * 86400;
        $this->bodies = ['https://iptoasn.com/data/ip2asn-combined.tsv.gz' => null];
        $this->assertFalse($database->refresh('iptoasn'), 'a failed fetch stores nothing');
        $this->now += 2 * 86400;
        $this->bodies = ['https://iptoasn.com/data/ip2asn-combined.tsv.gz' => gzencode("8.8.8.0\t8.8.8.255\t1\tUS\tX\n")];
        $this->assertFalse($database->refresh('iptoasn'), 'a file that parses to a handful of ranges is a truncated download');
        $this->assertSame(15169, $database->lookup('8.8.8.8')->asn, 'the earlier version still answers');
    }

    #[Test]
    public function a_feed_is_not_fetched_again_before_its_minimum_interval(): void
    {
        $this->bodies = ['https://iptoasn.com/data/ip2asn-combined.tsv.gz' => gzencode($this->fixture('ip2asn-sample.tsv'))];
        $database = $this->database(null, ['iptoasn' => NetworkFeedCatalogue::defaults()['iptoasn']]);

        $this->assertTrue($database->refresh('iptoasn'));
        $this->assertSame(1, $this->calls);
        $this->now += 3600;
        $this->assertFalse($database->refresh('iptoasn'));
        $this->assertSame(1, $this->calls, 'IPtoASN is fetched at most once a day');
    }

    #[Test]
    public function the_monthly_file_falls_back_to_last_month_when_this_months_is_not_published_yet(): void
    {
        $this->now = 1_793_664_000; // 2026-11-03
        $this->bodies = ['https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz' => gzencode($this->fixture('dbip-country-lite-sample.csv'))];
        $database = $this->database(null, ['dbip_country' => NetworkFeedCatalogue::defaults()['dbip_country']]);

        $this->assertTrue($database->refresh('dbip_country'));
        $this->assertSame(2, $this->calls, 'November first (404), then October');
        $this->assertSame('US', $database->lookup('8.8.8.8')->country);
    }

    #[Test]
    public function the_licence_findings_are_dated_and_an_unverified_feed_needs_the_hosts_consent(): void
    {
        foreach (NetworkFeedCatalogue::defaults() as $feed) {
            $this->assertTrue($feed->isUsableWithout(), $feed->key);
            $this->assertSame('2026-10-31', $feed->licence['checked_on']);
            $this->assertStringStartsWith('https://', $feed->urls[0]);
        }
        $this->assertStringContainsString('CC BY 4.0', NetworkFeedCatalogue::defaults()['dbip_country']->attribution);

        $unverified = new NetworkFeed('x', 'X', ['https://x.test/a.csv'], NetworkFeed::KIND_COUNTRY, ['status' => 'unverified', 'note' => '', 'source' => '', 'checked_on' => '2026-10-31']);
        $this->bodies = ['https://x.test/a.csv' => $this->fixture('dbip-country-lite-sample.csv')];

        $this->assertFalse($this->database(null, ['x' => $unverified])->refresh('x'), 'not loaded without consent');
        $this->assertTrue($this->database(null, ['x' => $unverified], ['x'])->refresh('x'));
        $this->assertCount(2, $this->database()->attribution(), 'DB-IP and bad-asn-list ask for credit; IPtoASN is public domain');
    }

    #[Test]
    public function reserved_and_not_routed_ranges_and_overlaps_are_dropped_not_stored(): void
    {
        $country = NetworkDatabase::parseCountryCsv("0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n1.0.0.128,1.0.1.255,NZ\n2.0.0.0,2.0.0.255,xx9\nbroken line\n");
        $this->assertSame(1, $country['records'], 'ZZ, the overlapping line and the malformed ones are not records');

        $asn = NetworkDatabase::parseAsnTsv("1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM\n");
        $this->assertSame(1, $asn['records'], 'ASN 0 is not routed space');
        $this->assertSame([], $asn['vpn']);
        $this->assertContains(218799, NetworkDatabase::parseAsnTsv($this->fixture('ip2asn-sample.tsv'))['vpn'], 'LITE-VPN-AS is classified at refresh time');
    }

    #[Test]
    public function a_range_that_crosses_shards_is_found_on_both_sides_of_the_boundary(): void
    {
        $buffers = [];
        RangeTable::add($buffers, inet_pton('9.255.255.0'), inet_pton('10.0.0.255'), 'XX');
        RangeTable::add($buffers, inet_pton('2001:0ff0::'), inet_pton('2001:1005::'), 'YY');

        $this->assertSame('XX', RangeTable::find($buffers['4:9'], inet_pton('9.255.255.200'), 2));
        $this->assertSame('XX', RangeTable::find($buffers['4:10'], inet_pton('10.0.0.1'), 2));
        $this->assertNull(RangeTable::find($buffers['4:10'], inet_pton('10.0.1.1'), 2));
        $this->assertNull(RangeTable::find($buffers['4:9'], inet_pton('9.255.254.1'), 2));
        $this->assertSame('YY', RangeTable::find($buffers[RangeTable::shardOf(inet_pton('2001:1000::1'))], inet_pton('2001:1000::1'), 2));
        $this->assertSame('YY', RangeTable::find($buffers[RangeTable::shardOf(inet_pton('2001:0ff5::1'))], inet_pton('2001:0ff5::1'), 2));
    }

    /**
     * @return array<string, array{0: string, 1: ?string}>
     */
    public static function asnNames(): array
    {
        return [
            'vpn name' => ['LITE-VPN-AS - LITE DIGITAL LTD', 'vpn'],
            'glued vpn' => ['SKYVPN', 'vpn'],
            'hosting' => ['DANBOT-HOSTING-LTD', 'hosting'],
            'data centre spelling' => ['Acme Data Centre BV', 'hosting'],
            'colo as a whole word' => ['Midwest Colo Services', 'hosting'],
            'an ordinary isp' => ['Koninklijke KPN N.V.', null],
            'colo inside a word' => ['University of Colorado', null],
            'empty' => ['', null],
        ];
    }

    #[Test]
    #[DataProvider('asnNames')]
    public function the_name_classifier_flags_only_what_the_name_says(string $name, ?string $category): void
    {
        $this->assertSame($category, AsnClassifier::classify($name));
    }

    #[Test]
    public function a_training_row_context_holds_a_country_and_a_bucket_and_nothing_that_identifies_a_network(): void
    {
        $facts = new NetworkFacts(NetworkFacts::STATE_OK, 'NL', 15169, NetworkFacts::CATEGORY_HOSTING);

        $this->assertSame(['country' => 'NL', 'asn_category' => 'hosting'], $facts->trainingBuckets());
        $this->assertSame(['country' => 'unknown', 'asn_category' => 'unknown'], NetworkFacts::unknown()->trainingBuckets());
        $this->assertSame('tor', (new NetworkFacts(NetworkFacts::STATE_OK, 'DE'))->withReputation(new ReputationResult(ReputationResult::STATE_OK, ['tor_exit']))->trainingBuckets()['asn_category']);
        $this->assertStringNotContainsString('15169', json_encode($facts->trainingBuckets()));
        $this->assertSame(['net_hosting' => 1.0], $facts->features());
        $this->assertTrue((new NetworkFacts(NetworkFacts::STATE_OK, 'NL'))->withReputation(new ReputationResult(ReputationResult::STATE_OK, ['datacenter']))->isHosting(), 'a published cloud range counts as hosting');
    }
}

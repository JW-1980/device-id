<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Detectors\ReviewItem;
use DeviceId\Signals\CountryBounds;
use DeviceId\Signals\Velocity;
use DeviceId\Signals\VelocityFinding;
use DeviceId\Signals\VelocityThresholds;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class VelocityTest extends TestCase
{
    private const NOW = 1_793_000_000;

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    // ------------------------------------------------------------------ bursts

    #[Test]
    public function a_burst_needs_the_configured_count_inside_the_window(): void
    {
        $thresholds = new VelocityThresholds(windowSeconds: 600, signupsPerDevice: 3);
        $recent = [self::NOW - 10, self::NOW - 100, self::NOW - 500];

        $finding = Velocity::burst('signup', 'device_key', 'dk1', $recent, self::NOW, $thresholds);
        $this->assertNotNull($finding);
        $this->assertSame(VelocityFinding::BURST, $finding->code);
        $this->assertSame(['event' => 'signup', 'count' => 3, 'limit' => 3, 'window_seconds' => 600], $finding->evidence);
        $this->assertSame(ReviewItem::SEVERITY_MEDIUM, $finding->severity);

        $this->assertNull(Velocity::burst('signup', 'device_key', 'dk1', [self::NOW - 10, self::NOW - 100], self::NOW, $thresholds), 'two is not three');
        $this->assertNull(Velocity::burst('signup', 'device_key', 'dk1', [self::NOW - 10, self::NOW - 100, self::NOW - 700], self::NOW, $thresholds), 'an event outside the window does not count');
        $this->assertNull(Velocity::burst('signup', 'device_key', 'dk1', [self::NOW - 10, self::NOW - 100, self::NOW + 50], self::NOW, $thresholds), 'nor does one from the future');
        $this->assertSame(ReviewItem::SEVERITY_HIGH, Velocity::burst('signup', 'device_key', 'dk1', array_fill(0, 6, self::NOW - 5), self::NOW, $thresholds)?->severity);
    }

    #[Test]
    public function a_shared_network_gets_a_higher_limit_and_a_lower_severity(): void
    {
        $thresholds = new VelocityThresholds(signupsPerDevice: 3, signupsPerNetwork: 8);
        $five = array_fill(0, 5, self::NOW - 60);

        $this->assertNotNull(Velocity::burst('signup', 'device_key', 'dk', $five, self::NOW, $thresholds));
        $this->assertNull(Velocity::burst('signup', 'network_hash', 'nh', $five, self::NOW, $thresholds), 'five sign-ups from one office address is ordinary');
        $this->assertSame(ReviewItem::SEVERITY_INFORMATIONAL, Velocity::burst('signup', 'network_hash', 'nh', array_fill(0, 8, self::NOW - 60), self::NOW, $thresholds)?->severity);
    }

    #[Test]
    public function the_thresholds_come_from_configuration_and_a_bad_value_is_refused(): void
    {
        Config::use(['fingerprint' => ['velocity' => ['window_seconds' => 120, 'logins_per_device' => 4, 'max_speed_kmh' => 'fast']]]);
        $fromConfig = VelocityThresholds::fromConfig();

        $this->assertSame(120, $fromConfig->windowSeconds);
        $this->assertSame(4, $fromConfig->loginsPerDevice);
        $this->assertSame(1000.0, $fromConfig->maxSpeedKmh, 'a wrong-typed value keeps the default, it is not coerced to 0');
        $this->assertNotNull(Velocity::burst('login', 'device_key', 'dk', array_fill(0, 4, self::NOW - 30), self::NOW), 'the default thresholds are read from configuration');
        $this->expectException(\InvalidArgumentException::class);
        new VelocityThresholds(windowSeconds: 0);
    }

    #[Test]
    public function an_unknown_event_kind_is_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Velocity::burst('purchase', 'device_key', 'dk', [self::NOW], self::NOW, new VelocityThresholds);
    }

    // ------------------------------------------------------------------ impossible travel

    #[Test]
    public function two_sessions_an_ocean_apart_minutes_apart_are_impossible(): void
    {
        $finding = Velocity::impossibleTravel('acct-1', [
            ['at' => self::NOW - 1200, 'country' => 'NL'],
            ['at' => self::NOW, 'country' => 'AU'],
        ], new VelocityThresholds);

        $this->assertNotNull($finding);
        $this->assertSame(VelocityFinding::IMPOSSIBLE_TRAVEL, $finding->code);
        $this->assertSame('account', $finding->subjectKind);
        $this->assertSame('NL', $finding->evidence['from_country']);
        $this->assertSame('AU', $finding->evidence['to_country']);
        $this->assertGreaterThan(1000, $finding->evidence['min_speed_kmh']);
        $this->assertSame(ReviewItem::SEVERITY_HIGH, $finding->severity);
        $this->assertSame('impossible_travel', $finding->toReviewItem()->detector);
        $this->assertSame([], array_filter(array_keys($finding->evidence), static fn (string $k): bool => str_contains($k, 'ip') || str_contains($k, 'address')), 'no address in the evidence');
    }

    #[Test]
    public function honest_travel_neighbours_unknowns_and_vpn_exits_are_silent(): void
    {
        $t = new VelocityThresholds;

        $this->assertNull(Velocity::impossibleTravel('a', [['at' => self::NOW - 7200, 'country' => 'NL'], ['at' => self::NOW, 'country' => 'DE']], $t), 'neighbours are 0 km apart as boxes');
        $this->assertNull(Velocity::impossibleTravel('a', [['at' => self::NOW - 40000, 'country' => 'NL'], ['at' => self::NOW, 'country' => 'AU']], $t), '11 hours for at least 5,900 km is under 1,000 km/h: possible by air');
        $this->assertNull(Velocity::impossibleTravel('a', [['at' => self::NOW - 1200, 'country' => 'NL'], ['at' => self::NOW, 'country' => null]], $t), 'an unknown country is no evidence');
        $this->assertNull(Velocity::impossibleTravel('a', [['at' => self::NOW - 1200, 'country' => 'NL'], ['at' => self::NOW, 'country' => 'ZZ']], $t), 'a code with no bounding box is no evidence');
        $this->assertNull(Velocity::impossibleTravel('a', [['at' => self::NOW - 1200, 'country' => 'NL', 'anonymised' => true], ['at' => self::NOW, 'country' => 'AU']], $t), 'a VPN exit says nothing about the person');
        $this->assertNull(Velocity::impossibleTravel('a', [['at' => self::NOW, 'country' => 'NL']], $t), 'one session');
        $this->assertNull(Velocity::impossibleTravel('a', [['at' => self::NOW - 5, 'country' => 'NL'], ['at' => self::NOW, 'country' => 'NL']], $t), 'same country');
    }

    #[Test]
    public function the_pair_is_judged_by_consecutive_sessions_in_time_order_and_the_worst_is_reported(): void
    {
        $finding = Velocity::impossibleTravel('a', [
            ['at' => self::NOW, 'country' => 'JP'],
            ['at' => self::NOW - 90000, 'country' => 'NL'],
            ['at' => self::NOW - 600, 'country' => 'NL'],
        ], new VelocityThresholds);

        $this->assertNotNull($finding, 'sessions given out of order are sorted first');
        $this->assertSame('NL', $finding->evidence['from_country']);
        $this->assertSame('JP', $finding->evidence['to_country']);
        $this->assertSame(600, $finding->evidence['seconds']);
    }

    #[Test]
    public function the_time_between_sessions_is_never_taken_below_the_floor(): void
    {
        $one = [['at' => self::NOW - 1, 'country' => 'NL'], ['at' => self::NOW, 'country' => 'JP']];

        $strict = Velocity::impossibleTravel('a', $one, new VelocityThresholds(minSecondsBetween: 1));
        $floored = Velocity::impossibleTravel('a', $one, new VelocityThresholds(minSecondsBetween: 3600, maxSpeedKmh: 20000.0));

        $this->assertNotNull($strict);
        $this->assertNull($floored, 'a one-second gap is treated as an hour when the floor says so');
    }

    #[Test]
    public function the_distance_is_a_lower_bound_between_boxes_and_never_larger_than_the_truth(): void
    {
        $this->assertSame(0.0, Velocity::minimumDistanceKm('FR', 'DE'));
        $this->assertSame(0.0, Velocity::minimumDistanceKm('US', 'CA'));
        $this->assertSame(0.0, Velocity::minimumDistanceKm('NZ', 'FJ'), 'across the antimeridian');
        $this->assertNull(Velocity::minimumDistanceKm('NL', 'QQ'));
        // Tokyo to Amsterdam is about 9,300 km; the bound for Japan and the Netherlands (Caribbean included) must not exceed it.
        $bound = Velocity::minimumDistanceKm('JP', 'NL');
        $this->assertGreaterThan(1000.0, $bound);
        $this->assertLessThan(9300.0, $bound);
        $this->assertEqualsWithDelta(Velocity::minimumDistanceKm('NL', 'JP'), $bound, 0.001, 'symmetric');
        $this->assertGreaterThan(200, count(CountryBounds::BOXES));
    }

    #[Test]
    public function findings_become_model_features_and_review_items(): void
    {
        $burst = new VelocityFinding(VelocityFinding::BURST, 'device_key', 'dk', ReviewItem::SEVERITY_MEDIUM, ['count' => 3]);
        $travel = new VelocityFinding(VelocityFinding::IMPOSSIBLE_TRAVEL, 'account', 'a', ReviewItem::SEVERITY_HIGH, []);

        $this->assertSame([], Velocity::features([]));
        $this->assertSame(['vel_burst' => 1.0], Velocity::features([$burst]));
        $this->assertSame(['vel_burst' => 1.0, 'vel_impossible_travel' => 1.0], Velocity::features([$burst, $travel]));
        $this->assertSame('velocity_burst', $burst->toReviewItem()->detector);
        $this->assertSame('account', $travel->toReviewItem()->subjectKind);
    }

    // ------------------------------------------------------------------ velocity v2: distinct counts over three windows

    /**
     * @return list<array{at: int, value: string}>
     */
    private static function events(string $prefix, int $count, int $secondsAgo): array
    {
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = ['at' => self::NOW - $secondsAgo - $i, 'value' => $prefix.$i];
        }

        return $out;
    }

    #[Test]
    public function distinct_accounts_on_one_device_are_counted_per_window(): void
    {
        $thresholds = new VelocityThresholds;
        $events = [...self::events('a', 3, 60), ...self::events('b', 2, 5 * 3600), ...self::events('c', 3, 3 * 86400)];

        $findings = Velocity::distinct(Velocity::ACCOUNTS_PER_DEVICE, 'dk1', $events, self::NOW, $thresholds);

        $byWindow = [];
        foreach ($findings as $finding) {
            $this->assertSame(VelocityFinding::DISTINCT, $finding->code);
            $this->assertSame('device_key', $finding->subjectKind);
            $byWindow[$finding->evidence['window']] = $finding->evidence['distinct'];
        }
        // 1h: a0-a2 = 3 (limit 3); 24h: a0-a2 + b0-b1 = 5 (limit 4); 7d: + c0-c2 = 8 (limit 6)
        $this->assertSame(['1h' => 3, '24h' => 5, '7d' => 8], $byWindow);
        $this->assertSame(['vel_accounts_per_device_1h' => 1.0, 'vel_accounts_per_device_24h' => 1.0, 'vel_accounts_per_device_7d' => 1.0], Velocity::features($findings));
    }

    #[Test]
    public function the_same_value_twice_counts_once_and_events_outside_a_window_are_ignored(): void
    {
        $thresholds = new VelocityThresholds;
        $repeated = array_fill(0, 20, ['at' => self::NOW - 30, 'value' => 'acct-1']);

        $this->assertSame([], Velocity::distinct(Velocity::ACCOUNTS_PER_DEVICE, 'dk1', $repeated, self::NOW, $thresholds), 'twenty logins of one account are one account');

        $old = self::events('a', 3, 2 * 3600);
        $windows = array_map(static fn (VelocityFinding $f): string => $f->evidence['window'], Velocity::distinct(Velocity::ACCOUNTS_PER_DEVICE, 'dk1', $old, self::NOW, $thresholds));
        $this->assertSame([], $windows, 'three accounts two hours ago: not in the 1 hour window, under the 24 hour and 7 day limits');

        $future = [...self::events('a', 2, 60), ['at' => self::NOW + 500, 'value' => 'later']];
        $this->assertSame([], Velocity::distinct(Velocity::ACCOUNTS_PER_DEVICE, 'dk1', $future, self::NOW, $thresholds), 'an event from the future is not counted');
    }

    #[Test]
    public function a_device_key_shared_by_the_k_floor_of_accounts_is_a_device_class_not_a_ring(): void
    {
        $thresholds = new VelocityThresholds(distinctKFloor: 20);

        $this->assertNotSame([], Velocity::distinct(Velocity::ACCOUNTS_PER_DEVICE, 'dk1', self::events('a', 19, 60), self::NOW, $thresholds));
        $this->assertSame([], Velocity::distinct(Velocity::ACCOUNTS_PER_DEVICE, 'dk1', self::events('a', 20, 60), self::NOW, $thresholds));
        $this->assertNotSame([], Velocity::distinct(Velocity::DEVICES_PER_ACCOUNT, 'acct', self::events('d', 25, 60), self::NOW, $thresholds), 'the k-floor is about device keys shared by accounts only');
    }

    #[Test]
    public function devices_per_account_and_emails_per_network_use_their_own_limits_and_severities(): void
    {
        $thresholds = new VelocityThresholds;

        $devices = Velocity::distinct(Velocity::DEVICES_PER_ACCOUNT, 'acct-7', self::events('d', 6, 60), self::NOW, $thresholds);
        $this->assertSame('account', $devices[0]->subjectKind);
        $this->assertSame(ReviewItem::SEVERITY_HIGH, $devices[0]->severity, '6 devices in an hour is double the limit of 3');
        $this->assertStringContainsString('second factor', $devices[0]->toReviewItem()->recommendation);

        $five = Velocity::distinct(Velocity::EMAILS_PER_NETWORK, 'net1', self::events('e', 5, 60), self::NOW, $thresholds);
        $this->assertSame([], $five, 'a campus puts five addresses behind one network honestly');
        $six = Velocity::distinct(Velocity::EMAILS_PER_NETWORK, 'net1', self::events('e', 6, 60), self::NOW, $thresholds);
        $this->assertSame('network_hash', $six[0]->subjectKind);
        $this->assertSame(ReviewItem::SEVERITY_INFORMATIONAL, $six[0]->severity);
        $this->assertSame(ReviewItem::SEVERITY_MEDIUM, Velocity::distinct(Velocity::EMAILS_PER_NETWORK, 'net1', self::events('e', 12, 60), self::NOW, $thresholds)[0]->severity);
        $this->assertSame(['vel_emails_per_network_1h' => 1.0], Velocity::features($six));
    }

    #[Test]
    public function the_distinct_limits_come_from_configuration_and_a_non_monotone_value_is_repaired_not_thrown(): void
    {
        Config::use(['fingerprint' => ['velocity' => ['distinct' => ['accounts_per_device' => ['1h' => 2, '24h' => 2, '7d' => 9]], 'distinct_k_floor' => 50]]]);
        $thresholds = VelocityThresholds::fromConfig();

        $this->assertSame(['1h' => 2, '24h' => 2, '7d' => 9], $thresholds->distinct['accounts_per_device']);
        $this->assertSame(['1h' => 3, '24h' => 5, '7d' => 8], $thresholds->distinct['devices_per_account'], 'unconfigured relations keep their defaults');
        $this->assertSame(50, $thresholds->distinctKFloor);

        Config::use(['fingerprint' => ['velocity' => ['distinct' => ['accounts_per_device' => ['1h' => 9, '24h' => 3, '7d' => 4]]]]]);
        $this->assertSame(['1h' => 9, '24h' => 9, '7d' => 9], VelocityThresholds::fromConfig()->distinct['accounts_per_device'], 'a longer window never has a lower limit');
    }

    #[Test]
    public function an_unknown_relation_and_a_decreasing_limit_are_refused(): void
    {
        try {
            Velocity::distinct('cookies_per_ip', 'x', [], self::NOW);
            $this->fail('unknown relation');
        } catch (\InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
        $this->expectException(\InvalidArgumentException::class);
        new VelocityThresholds(distinct: ['accounts_per_device' => ['1h' => 5, '24h' => 3, '7d' => 9]] + VelocityThresholds::DEFAULT_DISTINCT);
    }
}

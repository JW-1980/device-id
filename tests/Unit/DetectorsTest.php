<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Detectors\DetectorThresholds;
use DeviceId\Detectors\ReviewItem;
use DeviceId\Detectors\ReviewSink;
use DeviceId\Detectors\RingDetectors;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DetectorsTest extends TestCase
{
    #[Test]
    public function a_device_key_with_several_accounts_is_queued_and_a_quiet_one_is_not(): void
    {
        $items = RingDetectors::accountsPerDevice([
            ['device_key' => 'k-quiet', 'accounts' => 3, 'networks' => 1],
            ['device_key' => 'k-ring', 'accounts' => 5, 'networks' => 1],
        ]);

        $this->assertCount(1, $items);
        $this->assertSame('k-ring', $items[0]->subject);
        $this->assertSame('accounts_per_device', $items[0]->detector);
        $this->assertSame(ReviewItem::SEVERITY_MEDIUM, $items[0]->severity);
        $this->assertSame(5, $items[0]->evidence['accounts']);
    }

    #[Test]
    public function many_accounts_or_many_networks_raise_the_severity(): void
    {
        $items = RingDetectors::accountsPerDevice([
            ['device_key' => 'many', 'accounts' => 8, 'networks' => 1],
            ['device_key' => 'spread', 'accounts' => 4, 'networks' => 3],
        ]);

        $this->assertSame([ReviewItem::SEVERITY_HIGH, ReviewItem::SEVERITY_HIGH], array_map(static fn (ReviewItem $i): string => $i->severity, $items));
    }

    #[Test]
    public function a_key_shared_by_the_k_floor_of_accounts_is_a_device_class_not_a_ring(): void
    {
        $items = RingDetectors::accountsPerDevice([['device_key' => 'popular-phone', 'accounts' => 20, 'networks' => 15]]);

        $this->assertCount(1, $items);
        $this->assertSame('device_key_is_a_class', $items[0]->detector);
        $this->assertSame(ReviewItem::SEVERITY_INFORMATIONAL, $items[0]->severity);
        $this->assertStringContainsString('do not queue its accounts', $items[0]->recommendation);
    }

    #[Test]
    public function the_k_floor_is_configurable_and_the_class_boundary_moves_with_it(): void
    {
        $items = RingDetectors::accountsPerDevice([['device_key' => 'k', 'accounts' => 10]], new DetectorThresholds(kFloor: 10));

        $this->assertSame('device_key_is_a_class', $items[0]->detector);
    }

    #[Test]
    public function an_account_on_many_devices_is_queued(): void
    {
        $items = RingDetectors::devicesPerAccount([
            ['account' => 'a-few', 'devices' => 4, 'networks' => 2],
            ['account' => 'a-many', 'devices' => 6, 'networks' => 2],
            ['account' => 'a-takeover', 'devices' => 7, 'networks' => 5],
        ]);

        $this->assertSame(['a-takeover', 'a-many'], array_map(static fn (ReviewItem $i): string => $i->subject, $items));
        $this->assertSame(ReviewItem::SEVERITY_HIGH, $items[0]->severity);
    }

    #[Test]
    public function a_burst_needs_volume_ratio_and_a_baseline_of_at_least_the_k_floor(): void
    {
        $result = RingDetectors::networkBursts([
            ['network_hash' => 'quiet', 'count' => 10, 'baseline_mean' => 1, 'baseline_n' => 500],
            ['network_hash' => 'normal-busy', 'count' => 40, 'baseline_mean' => 30, 'baseline_n' => 500],
            ['network_hash' => 'burst', 'count' => 40, 'baseline_mean' => 4, 'baseline_n' => 500],
            ['network_hash' => 'new-network', 'count' => 90, 'baseline_mean' => 0, 'baseline_n' => 19],
        ]);

        $this->assertSame(['burst'], array_map(static fn (ReviewItem $i): string => $i->subject, $result['items']));
        $this->assertSame(1, $result['unjudged'], 'a baseline of 19 observations is below the k-floor and is not judged');
        $this->assertSame(10.0, $result['items'][0]->evidence['ratio']);
        $this->assertSame(ReviewItem::SEVERITY_HIGH, $result['items'][0]->severity);
    }

    #[Test]
    public function all_detectors_run_over_one_set_of_aggregates_most_severe_first(): void
    {
        $items = RingDetectors::all([
            'accounts_per_device' => [['device_key' => 'k', 'accounts' => 4, 'networks' => 1]],
            'devices_per_account' => [['account' => 'a', 'devices' => 20, 'networks' => 6]],
            'network_bursts' => [['network_hash' => 'n', 'count' => 100, 'baseline_mean' => 5, 'baseline_n' => 100]],
        ]);

        $this->assertSame(['high', 'high', 'medium'], array_map(static fn (ReviewItem $i): string => $i->severity, $items));
        $this->assertSame([], RingDetectors::all([]));
    }

    #[Test]
    public function items_go_to_the_hosts_queue_and_carry_counts_not_personal_values(): void
    {
        $sink = new class implements ReviewSink
        {
            /** @var list<ReviewItem> */
            public array $items = [];

            public function enqueue(ReviewItem $item): void
            {
                $this->items[] = $item;
            }
        };
        $items = RingDetectors::accountsPerDevice([['device_key' => 'k', 'accounts' => 5, 'networks' => 2]]);

        $this->assertSame(1, RingDetectors::enqueueAll($items, $sink));

        $this->assertSame('accounts_per_device', $sink->items[0]->toArray()['detector']);
        foreach ($sink->items[0]->evidence as $value) {
            $this->assertTrue(is_int($value) || is_float($value) || is_string($value));
        }
    }

    #[Test]
    public function silly_thresholds_are_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new DetectorThresholds(accountsPerDevice: 1);
    }
}

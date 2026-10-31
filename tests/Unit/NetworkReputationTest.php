<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Model\FeatureCatalogue;
use DeviceId\Signals\NetworkReputation;
use DeviceId\Signals\NetworkReputationThresholds;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The first-party network reputation that replaces a credited abuse list: the host's own
 * labelled history, with a k-floor, counter-evidence and no verdict.
 */
final class NetworkReputationTest extends TestCase
{
    #[Test]
    public function a_small_network_is_never_judged_however_bad_its_few_reports_look(): void
    {
        $result = NetworkReputation::assess(10, 10, 0, 0);

        $this->assertSame(NetworkReputation::INSUFFICIENT, $result->state);
        $this->assertSame([], $result->features());
    }

    #[Test]
    public function a_large_network_with_many_confirmed_devices_raises_the_soft_feature(): void
    {
        $result = NetworkReputation::assess(40, 12, 0, 0);

        $this->assertSame(NetworkReputation::BAD, $result->state);
        $this->assertSame(0.3, $result->badShare);
        $this->assertSame(['net_history_bad' => 1.0], $result->features());
        $this->assertTrue(FeatureCatalogue::knows('net_history_bad'));
    }

    #[Test]
    public function suspicion_counts_half_and_clearances_cancel_the_reports(): void
    {
        $this->assertSame(NetworkReputation::CLEAN, NetworkReputation::assess(40, 0, 20, 0)->state, '20 suspected devices are 10 weighted: 0.25 of 40, under the 0.3 share');
        $this->assertSame(NetworkReputation::BAD, NetworkReputation::assess(40, 0, 24, 0)->state, '24 suspected devices are 12 weighted: 0.3');
        $this->assertSame(NetworkReputation::CLEAN, NetworkReputation::assess(40, 12, 0, 12)->state, 'as many clearances as reports: clean');
        $this->assertSame(NetworkReputation::BAD, NetworkReputation::assess(40, 12, 0, 11)->state);
    }

    #[Test]
    public function a_handful_of_reports_on_a_big_network_is_noise(): void
    {
        $this->assertSame(NetworkReputation::CLEAN, NetworkReputation::assess(1000, 4, 0, 0)->state, 'under the minimum of 5 weighted devices');
        $this->assertSame(NetworkReputation::CLEAN, NetworkReputation::assess(1000, 100, 0, 0)->state, 'a tenth of a campus is not 30 %');
    }

    #[Test]
    public function the_thresholds_are_configurable_and_validated(): void
    {
        $strict = new NetworkReputationThresholds(kFloor: 5, minimumBad: 1.0, badShare: 0.1);
        $this->assertSame(NetworkReputation::BAD, NetworkReputation::assess(10, 1, 0, 0, $strict)->state);
        $this->expectException(\InvalidArgumentException::class);
        new NetworkReputationThresholds(badShare: 1.5);
    }
}

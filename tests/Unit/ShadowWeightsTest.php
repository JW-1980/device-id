<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Network\NetworkFacts;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Scoring\ShadowComparison;
use DeviceId\Scoring\ShadowWeights;
use DeviceId\Scoring\VerdictScorer;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Per-rule shadow weights, the `test` disposition: measured next to the live weights, never summed
 * into the verdict.
 */
final class ShadowWeightsTest extends TestCase
{
    private const WINDOWS_CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

    protected function setUp(): void
    {
        parent::setUp();
        Config::reset();
    }

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    /**
     * A Dutch clock and Dutch languages on a Windows Chrome: fires `ip_country_vs_locale` (5) from Spain.
     *
     * @return array<string, mixed>
     */
    private static function dutchClaims(): array
    {
        return [
            'tier1' => [
                'environment' => ['state' => 'ok', 'value' => [
                    'identity' => ['userAgent' => self::WINDOWS_CHROME, 'platform' => 'Win32', 'maxTouchPoints' => 0, 'language' => 'nl-NL', 'languages' => ['nl-NL', 'nl']],
                    'screen' => ['width' => 1920, 'height' => 1080],
                ]],
                'engineIdentity' => ['state' => 'ok', 'value' => ['engine' => 'v8', 'errorOwnProps' => 'message,stack', 'stackShape' => 'at', 'internalError' => false]],
            ],
            'tier2' => ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'nl-NL', 'timeZone' => 'Europe/Amsterdam']]]],
            'integrity' => ['findings' => [], 'data' => []],
        ];
    }

    private function compare(array $shadow, ?NetworkFacts $network = null): ?ShadowComparison
    {
        $consistency = new EnvironmentConsistency;
        $scorer = new VerdictScorer($consistency);
        $network ??= new NetworkFacts(NetworkFacts::STATE_OK, 'ES');
        $transport = new TransportIntegrityResult;
        $live = $scorer->score(self::dutchClaims(), $transport, network: $network);

        return (new ShadowWeights($consistency, $scorer))->compare(self::dutchClaims(), $transport, $network, $live, $shadow);
    }

    #[Test]
    public function a_higher_shadow_weight_shows_the_score_it_would_have_made_while_the_live_verdict_stays_as_it_was(): void
    {
        $comparison = $this->compare(['ip_country_vs_locale' => 25]);

        $this->assertNotNull($comparison);
        $this->assertSame(5, $comparison->liveWeight, 'ip_country_vs_locale is 5 live');
        $this->assertSame(25, $comparison->shadowWeight);
        $this->assertGreaterThan($comparison->liveScore, $comparison->shadowScore);
        $this->assertTrue($comparison->hadEffect());
        $this->assertSame([['code' => 'ip_country_vs_locale', 'live_weight' => 5, 'shadow_weight' => 25, 'fired' => true]], $comparison->changes);
        $this->assertSame('pass', $comparison->liveBand);
        $this->assertSame('elevated', $comparison->shadowBand);
        $this->assertTrue($comparison->wouldChangeBand());

        $live = (new VerdictScorer(new EnvironmentConsistency))->score(self::dutchClaims(), new TransportIntegrityResult, network: new NetworkFacts(NetworkFacts::STATE_OK, 'ES'));
        $this->assertSame(5, $live->totalWeight(), 'the shadow weight is never summed into the live verdict');
    }

    #[Test]
    public function a_rule_silenced_live_but_tested_shows_what_it_would_have_added(): void
    {
        Config::use(['fingerprint' => ['constraint_weights' => ['ip_country_vs_locale' => 0]]]);

        $comparison = $this->compare(['ip_country_vs_locale' => 8]);

        $this->assertNotNull($comparison);
        $this->assertSame(0, $comparison->liveWeight);
        $this->assertSame(8, $comparison->shadowWeight);
        $this->assertSame([['code' => 'ip_country_vs_locale', 'live_weight' => 0, 'shadow_weight' => 8, 'fired' => true]], $comparison->changes);
    }

    #[Test]
    public function a_tested_rule_that_does_not_fire_changes_nothing_and_says_so(): void
    {
        $comparison = $this->compare(['ip_country_vs_locale' => 25], new NetworkFacts(NetworkFacts::STATE_OK, 'NL'));

        $this->assertNotNull($comparison);
        $this->assertSame(0, $comparison->liveWeight);
        $this->assertSame(0, $comparison->shadowWeight);
        $this->assertFalse($comparison->hadEffect());
        $this->assertFalse($comparison->wouldChangeBand());
        $this->assertFalse($comparison->changes[0]['fired']);
    }

    #[Test]
    public function testing_a_weight_of_zero_shows_the_score_without_that_rule(): void
    {
        $comparison = $this->compare(['ip_country_vs_locale' => 0]);

        $this->assertNotNull($comparison);
        $this->assertSame(5, $comparison->liveWeight);
        $this->assertSame(0, $comparison->shadowWeight);
        $this->assertSame(0, $comparison->shadowScore);
    }

    #[Test]
    public function without_shadow_weights_there_is_nothing_to_compare_and_the_table_comes_from_configuration(): void
    {
        $this->assertNull($this->compare([]));

        Config::use(['fingerprint' => ['constraint_weights_shadow' => ['ip_country_vs_locale' => 999, 'not_numeric' => 'x', 'network_vpn' => -3]]]);
        $this->assertSame(['ip_country_vs_locale' => EnvironmentConsistency::MAX_WEIGHT, 'network_vpn' => 0], EnvironmentConsistency::shadowWeights(), 'bounded like the live weights; garbage dropped');

        $consistency = new EnvironmentConsistency;
        $scorer = new VerdictScorer($consistency);
        $network = new NetworkFacts(NetworkFacts::STATE_OK, 'ES');
        $live = $scorer->score(self::dutchClaims(), new TransportIntegrityResult, network: $network);
        $fromConfig = (new ShadowWeights($consistency, $scorer))->compare(self::dutchClaims(), new TransportIntegrityResult, $network, $live);
        $this->assertSame(EnvironmentConsistency::MAX_WEIGHT, $fromConfig?->shadowWeight);
    }

    #[Test]
    public function other_live_findings_are_carried_into_the_shadow_total_untouched(): void
    {
        $consistency = new EnvironmentConsistency;
        $scorer = new VerdictScorer($consistency);
        $network = new NetworkFacts(NetworkFacts::STATE_OK, 'ES', 16509, NetworkFacts::CATEGORY_HOSTING);
        $live = $scorer->score(self::dutchClaims(), new TransportIntegrityResult, network: $network);
        $this->assertSame(10, $live->totalWeight(), 'ip_country_vs_locale 5 + network_hosting 5');

        $comparison = (new ShadowWeights($consistency, $scorer))->compare(self::dutchClaims(), new TransportIntegrityResult, $network, $live, ['ip_country_vs_locale' => 20]);

        $this->assertSame(25, $comparison?->shadowWeight, '20 tested + 5 hosting carried over');
        $this->assertSame(10, $comparison->liveWeight);
        $this->assertGreaterThan($comparison->toArray()['live']['score'], $comparison->toArray()['shadow']['score']);
    }
}

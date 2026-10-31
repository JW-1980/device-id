<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Keys\DeviceKeys;
use DeviceId\Matching\DeviceCandidateSource;
use DeviceId\Matching\DeviceMatcher;
use DeviceId\Matching\FellegiSunter;
use DeviceId\Matching\JsonFileMatcherWeightsSource;
use DeviceId\Matching\LearnedMatcher;
use DeviceId\Matching\LearnedWeights;
use DeviceId\Matching\MatchCandidate;
use DeviceId\Matching\MatcherWeightsSource;
use DeviceId\Matching\MatchResult;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class LearnedMatcherTest extends TestCase
{
    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    /**
     * A population of pairs with known agreement rates, from a deterministic generator.
     * `fonts`: same devices agree 95 %, disagree 5 %; strangers agree 10 %, disagree 90 %.
     * `panel`: same agree 80 %, disagree 20 %; strangers agree 40 %, disagree 60 %.
     * `gpuMath`: agree-only, present for 50 % of pairs.
     *
     * @return list<array{c: array<string, bool>, slice: string, same: bool|null}>
     */
    private static function population(int $same, int $different, bool $labelled = true): array
    {
        mt_srand(7);
        $pairs = [];
        $draw = static fn (float $p): bool => mt_rand() / mt_getrandmax() < $p;
        for ($i = 0; $i < $same + $different; $i++) {
            $isSame = $i < $same;
            $c = ['fonts' => $draw($isSame ? 0.95 : 0.10), 'panel' => $draw($isSame ? 0.80 : 0.40)];
            if ($draw(0.5)) {
                $c['gpuMath'] = $isSame ? true : $draw(0.05);
            }
            $pairs[] = ['c' => $c, 'slice' => $i % 2 === 0 ? 'chromium:desktop' : 'webkit:mobile', 'same' => $labelled ? $isSame : null];
        }

        return $pairs;
    }

    #[Test]
    public function labelled_estimation_recovers_m_and_u_and_the_weights_are_asymmetric(): void
    {
        $weights = FellegiSunter::estimate(self::population(600, 1400));

        $this->assertNotNull($weights);
        $fonts = $weights->weights['fonts'];
        $this->assertEqualsWithDelta(0.95, $fonts['m_agree'], 0.03);
        $this->assertEqualsWithDelta(0.10, $fonts['u_agree'], 0.03);
        $this->assertEqualsWithDelta(log(0.95 / 0.10, 2), $fonts['agree'], 0.35);
        $this->assertEqualsWithDelta(log(0.05 / 0.90, 2), $fonts['disagree'], 0.5);
        $panel = $weights->weights['panel'];
        $this->assertGreaterThan(0.3, abs(abs($panel['agree']) - abs($panel['disagree'])), 'agree (+1.0 bit) and disagree (-1.6 bits) are not mirror images');
        $this->assertGreaterThan(abs($weights->weights['panel']['agree']), abs($fonts['agree']), 'fonts is the stronger evidence');
        $this->assertLessThan(0.0, $fonts['disagree']);
    }

    #[Test]
    public function an_agree_only_component_has_a_large_agree_weight_and_a_mild_absence(): void
    {
        $weights = FellegiSunter::estimate(self::population(600, 1400));

        $this->assertNotNull($weights);
        $this->assertGreaterThan(2.0, $weights->weights['gpuMath']['agree']);
    }

    #[Test]
    public function unlabelled_em_finds_the_same_ordering_of_evidence(): void
    {
        $weights = FellegiSunter::estimate(self::population(600, 1400, false), null, 200);

        $this->assertNotNull($weights);
        $this->assertGreaterThan($weights->weights['panel']['agree'], $weights->weights['fonts']['agree']);
        $this->assertGreaterThan(0.0, $weights->weights['fonts']['agree']);
    }

    #[Test]
    public function estimation_refuses_when_one_class_is_missing(): void
    {
        $this->assertNull(FellegiSunter::estimate(self::population(0, 100)));
        $this->assertNull(FellegiSunter::estimate(self::population(100, 2)));
        $this->assertNull(FellegiSunter::estimate([]));
    }

    #[Test]
    public function the_posterior_rises_with_agreement_and_falls_with_disagreement(): void
    {
        $weights = FellegiSunter::estimate(self::population(600, 1400));
        $this->assertNotNull($weights);

        $agree = $weights->posterior(['fonts' => true, 'panel' => true]);
        $disagree = $weights->posterior(['fonts' => false, 'panel' => false]);

        $this->assertGreaterThan(0.9, $agree);
        $this->assertLessThan(0.05, $disagree);
        $this->assertSame([], $weights->contributions(['unknown_component' => true]));
    }

    #[Test]
    public function promotion_needs_one_thousand_pairs_in_every_slice(): void
    {
        $short = FellegiSunter::estimate(self::population(600, 1400));
        $this->assertNotNull($short);
        $this->assertTrue($short->promotion()['promotable'], '1000 pairs in each of the two slices');

        $thin = FellegiSunter::estimate(self::population(300, 1000));
        $this->assertNotNull($thin);
        $promotion = $thin->promotion();
        $this->assertFalse($promotion['promotable']);
        $this->assertSame(['chromium:desktop' => 650, 'webkit:mobile' => 650], $promotion['short_slices']);

        $this->assertFalse((new LearnedWeights([], 0.0, []))->promotion()['promotable'], 'no slices is not promotable');
    }

    #[Test]
    public function the_weights_file_round_trips_and_rejects_the_wrong_schema(): void
    {
        $weights = FellegiSunter::estimate(self::population(600, 1400));
        $this->assertNotNull($weights);

        $again = LearnedWeights::fromArray(json_decode((string) json_encode($weights->toArray()), true));

        $this->assertEquals($weights->weights, $again?->weights);
        $this->assertNull(LearnedWeights::fromArray(['schema' => 'something-else']));
        $this->assertNull(LearnedWeights::fromArray(['schema' => LearnedWeights::SCHEMA, 'schema_version' => 1, 'prior_logit' => 0, 'weights' => ['fonts' => ['agree' => 1]]]));
    }

    #[Test]
    public function the_file_source_returns_null_for_a_missing_or_malformed_file(): void
    {
        $this->assertNull((new JsonFileMatcherWeightsSource('/nonexistent.json'))->load());

        $path = tempnam(sys_get_temp_dir(), 'w');
        $this->assertNotFalse($path);
        file_put_contents($path, '{broken');
        try {
            $this->assertNull((new JsonFileMatcherWeightsSource($path))->load());
        } finally {
            @unlink($path);
        }
    }

    // ---------------------------------------------------------------- the matcher integration

    public static function stored(): MatchCandidate
    {
        return new class implements MatchCandidate
        {
            public function matchId(): int
            {
                return 9;
            }

            public function matchClusterId(): int
            {
                return 9;
            }

            public function matchComponents(): array
            {
                return ['os' => 'linux', 'arch' => 'x64', 'touch' => 0, 'engine' => 'chromium', 'fonts' => 'aa,bb,cc', 'panel' => 1920, 'gpu' => 'webgpu:nvidia/ada'];
            }

            public function matchBrowserKey(): ?string
            {
                return null;
            }

            public function matchNetwork(): ?string
            {
                return null;
            }

            public function matchHardwareKey(): ?string
            {
                return 'hw';
            }
        };
    }

    private static function matcher(?LearnedMatcher $learned): DeviceMatcher
    {
        return new DeviceMatcher(new class implements DeviceCandidateSource
        {
            public function exact(string $browserKey, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, ?string $ipPrefix = null): ?MatchCandidate
            {
                return null;
            }

            public function candidates(?string $hardwareKey, ?string $blockTuple, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, int $maxCandidates): array
            {
                return [LearnedMatcherTest::stored()];
            }

            public function addBrowserKey(int $deviceId, string $browserKey, int $saltVersion): void {}
        }, $learned);
    }

    private static function seen(): DeviceKeys
    {
        return new DeviceKeys(null, 'hw', ['os' => 'linux', 'arch' => 'x64', 'touch' => 0, 'engine' => 'chromium', 'fonts' => 'aa,bb,cc', 'panel' => 1920, 'gpu' => 'webgpu:nvidia/ada'], 0.9, 1);
    }

    private static function source(?LearnedWeights $weights): MatcherWeightsSource
    {
        return new class($weights) implements MatcherWeightsSource
        {
            public function __construct(private ?LearnedWeights $weights) {}

            public function load(): ?LearnedWeights
            {
                return $this->weights;
            }
        };
    }

    /**
     * @param  array<string, int>  $sliceCounts
     */
    private static function pessimistic(array $sliceCounts): LearnedWeights
    {
        // Every component's agreement is worth almost nothing and the prior says "stranger".
        $weight = ['agree' => 0.1, 'disagree' => -0.1, 'm_agree' => 0.5, 'u_agree' => 0.45, 'm_disagree' => 0.4, 'u_disagree' => 0.45, 'n' => 10];

        return new LearnedWeights(['fonts' => $weight, 'panel' => $weight, 'gpu' => $weight, 'hardware_key' => $weight], -6.0, $sliceCounts);
    }

    #[Test]
    public function shadow_mode_logs_the_learned_posterior_and_leaves_the_decision_to_the_hand_matcher(): void
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 6, 'fonts' => 3, 'panel' => 1, 'gpu' => 3]]]]);
        $learned = new LearnedMatcher(self::source(self::pessimistic(['all' => 5000])), LearnedMatcher::MODE_SHADOW);

        $with = self::matcher($learned)->match(self::seen(), null);
        $without = self::matcher(null)->match(self::seen(), null);

        $this->assertSame(MatchResult::METHOD_HARDWARE, $with->method);
        $this->assertSame($without->posterior, $with->posterior, 'shadow does not move the decision');
        $this->assertNotNull($with->shadowPosterior);
        $this->assertLessThan(0.1, $with->shadowPosterior, 'the pessimistic weights disagree with the hand weights, visibly');
        $this->assertNull($without->shadowPosterior);
    }

    #[Test]
    public function active_without_promotion_runs_as_shadow(): void
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 6, 'fonts' => 3, 'panel' => 1, 'gpu' => 3]]]]);
        $learned = new LearnedMatcher(self::source(self::pessimistic(['chromium:desktop' => 999])), LearnedMatcher::MODE_ACTIVE);

        $this->assertSame(LearnedMatcher::MODE_SHADOW, $learned->effectiveMode(), '999 pairs is one short');
        $this->assertSame(MatchResult::METHOD_HARDWARE, self::matcher($learned)->match(self::seen(), null)->method);
    }

    #[Test]
    public function active_with_promotion_lets_the_learned_posterior_decide(): void
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 6, 'fonts' => 3, 'panel' => 1, 'gpu' => 3]]]]);
        $learned = new LearnedMatcher(self::source(self::pessimistic(['chromium:desktop' => 1000, 'webkit:mobile' => 1000])), LearnedMatcher::MODE_ACTIVE);

        $result = self::matcher($learned)->match(self::seen(), null);

        $this->assertSame(LearnedMatcher::MODE_ACTIVE, $learned->effectiveMode());
        $this->assertSame(MatchResult::METHOD_NEW, $result->method, 'the pessimistic learned weights now decide: a new device');
    }

    #[Test]
    public function no_weights_file_means_no_shadow_posterior_and_an_unchanged_decision(): void
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 6, 'fonts' => 3, 'panel' => 1, 'gpu' => 3]]]]);
        $learned = new LearnedMatcher(self::source(null), LearnedMatcher::MODE_ACTIVE);

        $result = self::matcher($learned)->match(self::seen(), null);

        $this->assertSame(MatchResult::METHOD_HARDWARE, $result->method);
        $this->assertNull($result->shadowPosterior);
        $this->assertSame(LearnedMatcher::MODE_SHADOW, $learned->effectiveMode());
    }

    #[Test]
    public function the_config_entry_point_is_off_unless_a_path_and_a_mode_are_set(): void
    {
        $this->assertNull(LearnedMatcher::fromConfig());

        Config::use(['fingerprint' => ['matcher_learned' => ['mode' => 'shadow', 'path' => '/x.json']]]);
        $this->assertNotNull(LearnedMatcher::fromConfig());

        Config::use(['fingerprint' => ['matcher_learned' => ['mode' => 'off', 'path' => '/x.json']]]);
        $this->assertNull(LearnedMatcher::fromConfig());
    }

    #[Test]
    public function comparisons_use_the_one_shared_rule_set(): void
    {
        $matcher = self::matcher(null);

        $comparisons = LearnedMatcher::comparisons($matcher, self::seen(), self::stored(), ['fonts_agree_jaccard' => 0.8, 'fonts_disagree_jaccard' => 0.3]);

        $this->assertTrue($comparisons['fonts']);
        $this->assertTrue($comparisons['panel']);
        $this->assertTrue($comparisons['hardware_key']);
        $this->assertArrayNotHasKey('browser_key', $comparisons, 'no browser key on either side says nothing');
    }
}

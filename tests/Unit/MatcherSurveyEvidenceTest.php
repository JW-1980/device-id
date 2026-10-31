<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\Keys\DeviceKeys;
use DeviceId\Matching\DeviceCandidateSource;
use DeviceId\Matching\DeviceMatcher;
use DeviceId\Matching\MatchCandidate;
use DeviceId\Matching\MatcherPolicy;
use DeviceId\Matching\MatchResult;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../tools/capture/CaptureAnalysis.php';

/**
 * The arXiv survey's matcher evidence (2026-10-31, section 3b) applied as hand defaults:
 * static GPU capabilities outweigh the output hash and the hash never vetoes, mobile and WebKit
 * need a stricter posterior to link, and keyboard layout is not counted twice with language.
 */
final class MatcherSurveyEvidenceTest extends TestCase
{
    public const HARDWARE = 'hw-key';

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    /**
     * @param  array<string, scalar|null>  $components
     */
    private static function keys(array $components): DeviceKeys
    {
        return new DeviceKeys(null, self::HARDWARE, $components + ['os' => 'ios', 'arch' => 'arm', 'touch' => 0, 'engine' => 'chromium'], 0.9, 1);
    }

    /**
     * @param  array<string, scalar|null>  $components
     */
    private static function candidate(array $components): MatchCandidate
    {
        return new class($components + ['os' => 'ios', 'arch' => 'arm', 'touch' => 0, 'engine' => 'chromium']) implements MatchCandidate
        {
            /** @param array<string, scalar|null> $components */
            public function __construct(private array $components) {}

            public function matchId(): int
            {
                return 3;
            }

            public function matchClusterId(): int
            {
                return 3;
            }

            public function matchComponents(): array
            {
                return $this->components;
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
                return MatcherSurveyEvidenceTest::HARDWARE;
            }
        };
    }

    private static function matcher(MatchCandidate $stored): DeviceMatcher
    {
        return new DeviceMatcher(new class($stored) implements DeviceCandidateSource
        {
            public function __construct(private MatchCandidate $stored) {}

            public function exact(string $browserKey, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, ?string $ipPrefix = null): ?MatchCandidate
            {
                return null;
            }

            public function candidates(?string $hardwareKey, ?string $blockTuple, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, int $maxCandidates): array
            {
                return [$this->stored];
            }

            public function addBrowserKey(int $deviceId, string $browserKey, int $saltVersion): void {}
        });
    }

    // ---------------------------------------------------------------- gpuCaps against gpuMath

    #[Test]
    public function static_gpu_capabilities_outweigh_the_output_hash_by_default(): void
    {
        $policy = MatcherPolicy::current();

        $weights = $policy->effectiveWeights(['gpuMath' => 2]);

        $this->assertGreaterThan($weights['gpuMath'], $weights['gpuCaps']);
        $this->assertSame(3, $weights['gpuCaps']);
    }

    #[Test]
    public function a_host_that_raised_the_hash_without_mentioning_capabilities_still_gets_capabilities_above_it(): void
    {
        $weights = MatcherPolicy::current()->effectiveWeights(['gpuMath' => 5]);

        $this->assertSame(6, $weights['gpuCaps']);
    }

    #[Test]
    public function an_explicit_host_weight_for_capabilities_is_respected_including_zero(): void
    {
        $this->assertSame(0, MatcherPolicy::current()->effectiveWeights(['gpuCaps' => 0, 'gpuMath' => 2])['gpuCaps']);
        $this->assertSame(1, MatcherPolicy::current()->effectiveWeights(['gpuCaps' => 1, 'gpuMath' => 2])['gpuCaps']);
    }

    #[Test]
    public function a_matching_capability_list_moves_the_posterior_more_than_a_matching_output_hash(): void
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 2, 'gpuMath' => 2]]]]);
        $caps = self::matcher(self::candidate(['gpuCaps' => 'caps:chromium:1', 'gpu' => 'webgl:chromium:aa']))->match(self::keys(['gpuCaps' => 'caps:chromium:1', 'gpu' => 'webgl:chromium:aa']), null);
        $math = self::matcher(self::candidate(['gpuMath' => 'gpumath:1', 'gpu' => 'webgl:chromium:aa']))->match(self::keys(['gpuMath' => 'gpumath:1', 'gpu' => 'webgl:chromium:aa']), null);

        $this->assertGreaterThan($math->posterior, $caps->posterior);
    }

    #[Test]
    public function the_output_hash_never_vetoes_even_when_a_host_lists_it_as_a_veto_component(): void
    {
        Config::use(['fingerprint' => ['matcher' => [
            'weights' => ['hardware_key' => 10, 'fonts' => 1], 'veto_components' => ['fonts', 'gpu', 'gpuMath'],
        ]]]);
        $stored = self::candidate(['fonts' => 'aa,bb,cc', 'gpuMath' => 'gpumath:old']);
        $seen = self::keys(['fonts' => 'aa,bb,cc', 'gpuMath' => 'gpumath:new']);

        $result = self::matcher($stored)->match($seen, null);

        $this->assertSame(MatchResult::METHOD_HARDWARE, $result->method, (string) $result->linkVeto);
        $this->assertNull($result->linkVeto);
    }

    #[Test]
    public function mutatio_n_a_real_veto_component_still_vetoes(): void
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 10, 'fonts' => 1], 'veto_components' => ['fonts']]]]);
        $stored = self::candidate(['fonts' => 'aa,bb,cc,dd,ee,ff']);
        $seen = self::keys(['fonts' => 'xx,yy,zz,uu,vv,ww']);

        $this->assertSame(MatchResult::VETO_HIGH_ENTROPY_DISAGREEMENT, self::matcher($stored)->match($seen, null)->linkVeto, 'the never-veto list must not have swallowed every veto');
    }

    // ---------------------------------------------------------------- stricter threshold

    /** hardware_key 6 and nothing else: score 6, posterior sigmoid((6 - 3) / 1.5) = 0.8808, between link (0.8) and the stricter 0.9. */
    private function postureFor(array $seen, array $stored): MatchResult
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 6, 'gpu' => 0]]]]);
        // `gpu` agrees (a high-entropy agreement) but weighs nothing, so the score is the hardware key alone.
        $gpu = ['gpu' => 'webgl:chromium:aa'];

        return self::matcher(self::candidate($stored + $gpu))->match(self::keys($seen + $gpu), null);
    }

    #[Test]
    public function desktop_chromium_links_at_a_posterior_of_0_88(): void
    {
        $result = $this->postureFor([], []);

        $this->assertEqualsWithDelta(0.8808, $result->posterior, 1e-4);
        $this->assertSame(MatchResult::METHOD_HARDWARE, $result->method);
    }

    #[Test]
    public function a_touch_device_needs_the_stricter_posterior_and_is_only_possible_at_0_88(): void
    {
        $result = $this->postureFor(['touch' => 1], ['touch' => 1]);

        $this->assertEqualsWithDelta(0.8808, $result->posterior, 1e-4);
        $this->assertSame(MatchResult::METHOD_POSSIBLE, $result->method);
        $this->assertSame(MatchResult::VETO_STRICTER_THRESHOLD, $result->linkVeto);
        $this->assertNull($result->deviceId, 'a possible match links nothing');
        $this->assertSame(3, $result->candidateId, 'the candidate is still recorded');
    }

    #[Test]
    public function webkit_on_either_side_needs_the_stricter_posterior(): void
    {
        $this->assertSame(MatchResult::VETO_STRICTER_THRESHOLD, $this->postureFor(['engine' => 'webkit'], ['engine' => 'chromium'])->linkVeto);
        $this->assertSame(MatchResult::VETO_STRICTER_THRESHOLD, $this->postureFor(['engine' => 'chromium'], ['engine' => 'webkit'])->linkVeto);
    }

    #[Test]
    public function a_stronger_mobile_match_still_links(): void
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 8, 'gpu' => 0]]]]);
        $gpu = ['gpu' => 'webgl:chromium:aa', 'touch' => 1];

        $result = self::matcher(self::candidate($gpu))->match(self::keys($gpu), null);

        $this->assertSame(MatchResult::METHOD_HARDWARE, $result->method, 'score 8 is posterior 0.97, above the stricter 0.9');
    }

    #[Test]
    public function the_stricter_posterior_is_configurable_and_never_below_the_ordinary_one(): void
    {
        Config::use(['fingerprint' => ['matcher_policy' => ['mobile_webkit_link_posterior' => 0.5]]]);

        $this->assertSame(0.8, MatcherPolicy::current()->linkPosteriorFor(['touch' => 1], [], 0.8));

        Config::use(['fingerprint' => ['matcher_policy' => ['mobile_webkit_link_posterior' => 0.97]]]);
        $this->assertSame(0.97, MatcherPolicy::current()->linkPosteriorFor(['engine' => 'webkit'], [], 0.8));
        $this->assertSame(0.8, MatcherPolicy::current()->linkPosteriorFor(['engine' => 'chromium', 'touch' => 0], ['engine' => 'gecko'], 0.8), 'desktop is unaffected');
    }

    // ---------------------------------------------------------------- keyboard and language

    /**
     * @param  array<string, scalar|null>  $mine
     * @param  array<string, scalar|null>  $theirs
     */
    private static function score(array $mine, array $theirs): int
    {
        return self::matcher(self::candidate($theirs))->score(self::keys($mine), self::candidate($theirs), ['keyboard' => 2, 'voices' => 2]);
    }

    #[Test]
    public function keyboard_counts_on_its_own_but_not_on_top_of_an_agreeing_voice_set(): void
    {
        $this->assertSame(2, self::score(['keyboard' => 'keyboard:a'], ['keyboard' => 'keyboard:a']), 'alone it counts');
        $this->assertSame(2, self::score(['keyboard' => 'keyboard:a', 'voices' => 'v1'], ['keyboard' => 'keyboard:a', 'voices' => 'v1']), 'voices count, keyboard does not: one fact, one vote');
    }

    #[Test]
    public function a_disagreeing_voice_set_does_not_remove_the_keyboard_vote(): void
    {
        $this->assertSame(0, self::score(['keyboard' => 'keyboard:a', 'voices' => 'v1'], ['keyboard' => 'keyboard:a', 'voices' => 'v2']), 'keyboard +2, voices -2');
    }

    #[Test]
    public function the_double_count_guard_can_be_switched_off(): void
    {
        Config::use(['fingerprint' => ['matcher_policy' => ['keyboard_independent_of_language' => true]]]);

        $this->assertSame(4, self::score(['keyboard' => 'keyboard:a', 'voices' => 'v1'], ['keyboard' => 'keyboard:a', 'voices' => 'v1']));
    }

    // ---------------------------------------------------------------- same machine still links

    #[Test]
    public function chromium_and_firefox_headed_on_one_machine_still_link_with_the_survey_defaults(): void
    {
        CaptureAnalysis::configure();
        $directory = __DIR__.'/../Fixtures/fingerprint/captures/';
        $chromium = json_decode((string) file_get_contents($directory.'linux-container.linux.chromium.headed.automation.json'), true);
        $firefox = json_decode((string) file_get_contents($directory.'linux-container.linux.firefox.headed.automation.json'), true);

        foreach ([CaptureAnalysis::match($chromium, $firefox), CaptureAnalysis::match($firefox, $chromium)] as $result) {
            $this->assertNotNull($result);
            $this->assertTrue($result['linked'], json_encode($result));
            $this->assertNull($result['veto']);
        }
    }
}

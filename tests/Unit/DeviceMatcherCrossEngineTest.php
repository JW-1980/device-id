<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Keys\DeviceComponents;
use DeviceId\Keys\DeviceKeys;
use DeviceId\Matching\DeviceCandidateSource;
use DeviceId\Matching\DeviceMatcher;
use DeviceId\Matching\MatchCandidate;
use DeviceId\Matching\MatchResult;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The matcher across engines: one device seen from two browsers must not be vetoed by a
 * component that two engines report differently by construction (WebGPU adapter strings, the
 * font set of a WebKit that hides user fonts), and two machines that really differ must still
 * be told apart.
 */
final class DeviceMatcherCrossEngineTest extends TestCase
{
    public const HARDWARE_KEY = 'hardware-key-of-one-mac';

    protected function setUp(): void
    {
        parent::setUp();
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['hardware_key' => 10, 'gpu' => 3, 'fonts' => 3, 'panel' => 3, 'gpuCaps' => 2, 'keyboard' => 1]]]]);
    }

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
        $base = ['os' => 'macos', 'arch' => 'arm', 'touch' => 0];

        return new DeviceKeys(null, self::HARDWARE_KEY, $components + $base, 0.9, 1);
    }

    /**
     * @param  array<string, scalar|null>  $components
     */
    private static function candidate(array $components): MatchCandidate
    {
        return new class($components + ['os' => 'macos', 'arch' => 'arm', 'touch' => 0]) implements MatchCandidate
        {
            /** @param array<string, scalar|null> $components */
            public function __construct(private array $components) {}

            public function matchId(): int
            {
                return 7;
            }

            public function matchClusterId(): int
            {
                return 7;
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
                return DeviceMatcherCrossEngineTest::HARDWARE_KEY;
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

    // ---------------------------------------------------------------- WebGPU class

    #[Test]
    public function safari_and_chrome_on_one_mac_are_the_same_device_although_their_webgpu_strings_differ(): void
    {
        // WebKit reports the vendor word as architecture too; Chromium reports Dawn's architecture.
        $safari = self::keys(['gpu' => 'webgpu:apple/apple', 'engine' => 'webkit', 'panel' => 3024]);
        $chrome = self::candidate(['gpu' => 'webgpu:apple/metal-3', 'engine' => 'chromium', 'panel' => 3024]);

        $result = self::matcher($chrome)->match($safari, null);

        $this->assertSame(MatchResult::METHOD_HARDWARE, $result->method, (string) $result->linkVeto);
        $this->assertNull($result->linkVeto);
        $this->assertSame(7, $result->deviceId);
    }

    #[Test]
    public function two_different_gpu_vendors_are_still_a_veto_across_engines(): void
    {
        $safari = self::keys(['gpu' => 'webgpu:apple/apple', 'engine' => 'webkit', 'panel' => 3024]);
        $other = self::candidate(['gpu' => 'webgpu:nvidia/ada', 'engine' => 'chromium', 'panel' => 3024]);

        $result = self::matcher($other)->match($safari, null);

        $this->assertSame(MatchResult::METHOD_POSSIBLE, $result->method);
        $this->assertSame(MatchResult::VETO_HIGH_ENTROPY_DISAGREEMENT, $result->linkVeto);
    }

    #[Test]
    public function within_one_engine_the_architecture_still_separates_two_gpus_of_one_vendor(): void
    {
        $matcher = self::matcher(self::candidate(['gpu' => 'webgpu:nvidia/turing', 'engine' => 'chromium', 'panel' => 2560]));
        $ada = self::keys(['gpu' => 'webgpu:nvidia/ada', 'engine' => 'chromium', 'panel' => 2560]);
        $turing = self::keys(['gpu' => 'webgpu:nvidia/turing', 'engine' => 'chromium', 'panel' => 2560]);

        $this->assertSame(MatchResult::VETO_HIGH_ENTROPY_DISAGREEMENT, $matcher->match($ada, null)->linkVeto);
        $this->assertSame(MatchResult::METHOD_HARDWARE, $matcher->match($turing, null)->method);
    }

    #[Test]
    public function a_webgpu_class_against_a_webgl_class_is_incomparable_not_a_disagreement(): void
    {
        // Firefox on Linux has no WebGPU: its class is the engine-conditioned WebGL hash.
        $firefox = self::keys(['gpu' => 'webgl:gecko:0123456789abcdef', 'engine' => 'gecko', 'panel' => 1920, 'fonts' => 'aa,bb,cc']);
        $chrome = self::candidate(['gpu' => 'webgpu:intel/gen-12', 'engine' => 'chromium', 'panel' => 1920, 'fonts' => 'aa,bb,cc']);

        $result = self::matcher($chrome)->match($firefox, null);

        $this->assertNotSame(MatchResult::VETO_HIGH_ENTROPY_DISAGREEMENT, $result->linkVeto);
        $this->assertSame(MatchResult::METHOD_HARDWARE, $result->method);
    }

    #[Test]
    public function an_empty_vendor_is_no_evidence(): void
    {
        // Firefox returns empty WebGPU strings; the component builder already falls back to WebGL
        // for those, but a stored `webgpu:/` must not agree with everything either.
        $matcher = self::matcher(self::candidate(['gpu' => 'webgpu:/', 'engine' => 'gecko', 'panel' => 1920]));
        $result = $matcher->match(self::keys(['gpu' => 'webgpu:/', 'engine' => 'chromium', 'panel' => 1920]), null);

        $this->assertNotSame(MatchResult::METHOD_HARDWARE, $result->method, 'two empty vendors are not an agreement');
    }

    // ---------------------------------------------------------------- fonts

    #[Test]
    public function a_webkit_font_set_that_hides_user_fonts_is_not_a_veto_against_another_engine(): void
    {
        $safari = self::keys(['gpu' => 'webgpu:apple/apple', 'engine' => 'webkit', 'panel' => 3024, 'fonts' => 'aa,bb']);
        $chrome = self::candidate(['gpu' => 'webgpu:apple/metal-3', 'engine' => 'chromium', 'panel' => 3024, 'fonts' => 'cc,dd,ee,ff,gg,hh']);

        $result = self::matcher($chrome)->match($safari, null);

        $this->assertNotSame(MatchResult::VETO_HIGH_ENTROPY_DISAGREEMENT, $result->linkVeto);
        $this->assertSame(MatchResult::METHOD_HARDWARE, $result->method);
    }

    #[Test]
    public function the_same_font_disagreement_within_one_engine_is_still_a_veto(): void
    {
        $one = self::keys(['gpu' => 'webgpu:apple/metal-3', 'engine' => 'chromium', 'panel' => 3024, 'fonts' => 'aa,bb']);
        $other = self::candidate(['gpu' => 'webgpu:apple/metal-3', 'engine' => 'chromium', 'panel' => 3024, 'fonts' => 'cc,dd,ee,ff,gg,hh']);

        $this->assertSame(MatchResult::VETO_HIGH_ENTROPY_DISAGREEMENT, self::matcher($other)->match($one, null)->linkVeto);
    }

    // ---------------------------------------------------------------- the agree-only components

    /**
     * @param  array<string, scalar|null>  $mine
     * @param  array<string, scalar|null>  $theirs
     */
    private static function score(array $mine, array $theirs): int
    {
        $weights = ['gpuCaps' => 2, 'keyboard' => 1, 'gpu' => 3, 'gpuMath' => 2];

        return (new DeviceMatcher(new class implements DeviceCandidateSource
        {
            public function exact(string $browserKey, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, ?string $ipPrefix = null): ?MatchCandidate
            {
                return null;
            }

            public function candidates(?string $hardwareKey, ?string $blockTuple, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, int $maxCandidates): array
            {
                return [];
            }

            public function addBrowserKey(int $deviceId, string $browserKey, int $saltVersion): void {}
        }))->score(self::keys($mine), self::candidate($theirs), $weights);
    }

    #[Test]
    public function keyboard_and_gpu_capabilities_only_ever_add_to_a_score(): void
    {
        $this->assertSame(1, self::score(['keyboard' => 'keyboard:aaaa'], ['keyboard' => 'keyboard:aaaa']));
        $this->assertSame(0, self::score(['keyboard' => 'keyboard:aaaa'], ['keyboard' => 'keyboard:bbbb']), 'a layout change is not another device');

        $same = 'caps:chromium:1111';
        $this->assertSame(2, self::score(['gpuCaps' => $same, 'engine' => 'chromium'], ['gpuCaps' => $same, 'engine' => 'chromium']));
        $this->assertSame(0, self::score(['gpuCaps' => $same, 'engine' => 'chromium'], ['gpuCaps' => 'caps:chromium:2222', 'engine' => 'chromium']), 'a driver update is not another device');
        $this->assertSame(0, self::score(['gpuCaps' => 'caps:chromium:1111'], ['gpuCaps' => 'caps:gecko:1111']), 'two engines\' lists are incomparable');
    }

    #[Test]
    public function the_new_components_are_in_the_shipped_component_list(): void
    {
        foreach (['keyboard', 'gpuCaps', 'codecsHw'] as $name) {
            $this->assertContains($name, DeviceComponents::SOFT);
        }
    }
}

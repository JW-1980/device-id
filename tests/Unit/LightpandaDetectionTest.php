<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\CheckRegistry;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../tools/capture/CaptureAnalysis.php';

/**
 * Lightpanda (https://github.com/lightpanda-io/browser, a Zig browser with V8, no layout and no
 * rendering) against `render_surfaces_stubbed` (this file), together with the name-based
 * `ua_headless_token` and the `media_hover_unanswered` tell (AgentShapeRulesTest).
 *
 * The fixtures under `tests/Fixtures/fingerprint/redteam/lightpanda-container.*` are real runs: the
 * 2026-11-04 nightly (`1.1.0-nightly.11647+b8e234a77`, Linux x86_64) driven over CDP by puppeteer-core
 * against the capture harness with the real collector. `lightpanda` is the default User-Agent;
 * `lightpanda-spoofed` is what an attacker does, because Lightpanda itself refuses any Mozilla
 * User-Agent: an init script rewriting `navigator.*` and `userAgentData`, and a proxy rewriting the
 * User-Agent and Sec-CH-UA request headers.
 */
final class LightpandaDetectionTest extends TestCase
{
    private const REDTEAM = __DIR__.'/../Fixtures/fingerprint/redteam';

    private const CAPTURES = __DIR__.'/../Fixtures/fingerprint/captures';

    private const DEFAULT_RUN = 'lightpanda-container.linux.lightpanda.headless.spoof-lightpanda';

    private const SPOOFED_RUN = 'lightpanda-container.linux.lightpanda-spoofed.headless.spoof-lightpanda-spoofed';

    private const CODES = ['render_surfaces_stubbed', 'media_hover_unanswered'];

    protected function setUp(): void
    {
        parent::setUp();
        CaptureAnalysis::configure();
    }

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    /**
     * @return array<string, mixed>
     */
    private static function record(string $path): array
    {
        /** @var array<string, mixed> $record */
        $record = json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);

        return $record;
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function honestRuns(): array
    {
        $files = [
            ...(glob(self::CAPTURES.'/*.json') ?: []),
            ...array_filter(glob(self::REDTEAM.'/*.json') ?: [], static fn (string $f): bool => ! str_contains($f, 'lightpanda') && basename($f) !== 'expectations.json'),
            ...(glob(self::REDTEAM.'/lightpanda-container.*baseline*.json') ?: []),
        ];
        sort($files);
        $out = [];
        foreach ($files as $file) {
            $out[basename($file, '.json')] = [$file];
        }

        return $out;
    }

    #[Test]
    public function the_default_lightpanda_run_is_blocked_by_independent_evidence(): void
    {
        $answer = CaptureAnalysis::analyse(self::record(self::REDTEAM.'/'.self::DEFAULT_RUN.'.json'))['merged'];

        $this->assertSame('block', $answer['band'], json_encode($answer['codes']));
        foreach (['ua_headless_token', 'render_surfaces_stubbed', 'media_hover_unanswered', 'canvas_winding_false'] as $code) {
            $this->assertArrayHasKey($code, $answer['codes']);
        }
        $this->assertSame(30, $answer['codes']['render_surfaces_stubbed']['weight']);
    }

    #[Test]
    public function the_default_run_carries_the_name_in_every_place_the_engine_reads(): void
    {
        $record = self::record(self::REDTEAM.'/'.self::DEFAULT_RUN.'.json');
        $claims = CaptureAnalysis::mergedClaims($record);

        $this->assertSame('Lightpanda/1.0', $claims['tier1']['environment']['identity']['userAgent']);
        $this->assertSame('Lightpanda', $claims['tier1']['uaClientHints']['brands'][0]['brand']);
        $headers = array_column($record['transport']['claims_request_headers'], 1, 0);
        $this->assertSame('Lightpanda/1.0', $headers['User-Agent']);
        $this->assertStringContainsString('"Lightpanda"', $headers['Sec-Ch-Ua']);
    }

    #[Test]
    public function the_spoofed_run_loses_the_name_but_the_engine_still_reads_as_stubbed(): void
    {
        $record = self::record(self::REDTEAM.'/'.self::SPOOFED_RUN.'.json');
        $claims = CaptureAnalysis::mergedClaims($record);
        $this->assertStringContainsString('Chrome/', $claims['tier1']['environment']['identity']['userAgent']);
        $headers = array_change_key_case(array_column($record['transport']['claims_request_headers'], 1, 0));
        $this->assertStringContainsString('Chrome/', $headers['user-agent']);
        $this->assertStringNotContainsString('Lightpanda', $headers['sec-ch-ua']);

        $answer = CaptureAnalysis::analyse($record)['merged'];
        $this->assertArrayNotHasKey('ua_headless_token', $answer['codes']);
        $this->assertArrayHasKey('render_surfaces_stubbed', $answer['codes']);
        $this->assertContains($answer['band'], ['challenge', 'block']);
    }

    #[Test]
    public function the_stub_rule_alone_flags_a_clean_spoof_with_no_javascript_lie_left(): void
    {
        $record = self::record(self::REDTEAM.'/'.self::SPOOFED_RUN.'.json');
        $claims = CaptureAnalysis::mergedClaims($record);
        // Remove every claim a JavaScript spoof leaves behind except the layout/rendering facts.
        $claims['integrity']['findings'] = [['code' => 'canvas_winding_false']];
        $codes = array_column((new EnvironmentConsistency)->contradictions($claims, CaptureAnalysis::transport($record)), 'code');

        $this->assertContains('render_surfaces_stubbed', $codes);
    }

    #[Test]
    #[DataProvider('honestRuns')]
    public function no_honest_capture_fires_either_code(string $path): void
    {
        $answer = CaptureAnalysis::analyse(self::record($path))['merged'];

        foreach (self::CODES as $code) {
            $this->assertArrayNotHasKey($code, $answer['codes'], basename($path));
        }
    }

    #[Test]
    public function the_recorded_claim_fixtures_fire_neither_code(): void
    {
        $files = glob(__DIR__.'/../Fixtures/fingerprint/claims-*.json') ?: [];
        $this->assertNotSame([], $files);
        foreach ($files as $file) {
            $claims = json_decode((string) file_get_contents($file), true, 64, JSON_THROW_ON_ERROR);
            $codes = array_column((new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult), 'code');
            foreach (self::CODES as $code) {
                $this->assertNotContains($code, $codes, basename($file));
            }
        }
    }

    /**
     * @param  array<string, float|int>  $base
     * @return array<string, mixed>
     */
    private static function layoutClaims(array $base, bool $everythingCollides, ?int $metrics, mixed $gpu, bool $winding): array
    {
        $names = ['Arial', 'Helvetica', 'Georgia', 'Impact', 'Verdana', 'Tahoma', 'Roboto', 'Courier'];
        $resolve = [];
        foreach ($names as $n => $name) {
            $resolve[$name] = ['width' => 100.0, 'collides' => $everythingCollides || $n > 0 ? array_keys($base) : []];
        }

        return [
            'tier1' => ['environment' => ['identity' => ['userAgent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36']]],
            'tier2' => [
                'fontFallback' => ['base' => $base, 'resolve' => $resolve],
                'fontMetrics' => ['count' => $metrics, 'pairs' => ''],
                'gpu' => $gpu,
            ],
            'integrity' => ['findings' => $winding ? [['code' => 'canvas_winding_false']] : [], 'data' => []],
        ];
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function layoutCases(): array
    {
        $same = ['monospace' => 100.0, 'sans-serif' => 100.0, 'serif' => 100.0, 'cursive' => 100.0, 'fantasy' => 100.0, 'system-ui' => 100.0];
        $differ = ['monospace' => 90.0, 'sans-serif' => 100.0, 'serif' => 95.0, 'cursive' => 100.0, 'fantasy' => 100.0, 'system-ui' => 100.0];
        $noGl = ['webgl' => null, 'webgpu' => null];
        $gl = ['webgl' => ['renderer' => 'ANGLE'], 'webgpu' => null];

        return [
            'Lightpanda: identical widths, no GL, stub canvas' => [self::layoutClaims($same, true, 0, $noGl, true), true],
            'identical widths and no GL, canvas fine' => [self::layoutClaims($same, true, 0, $noGl, false), true],
            'identical widths, GL present, stub canvas' => [self::layoutClaims($same, true, 0, $gl, true), true],
            'identical widths, GL present, canvas fine (a font-less container with a GPU)' => [self::layoutClaims($same, true, 0, $gl, false), false],
            'fonts matter, no GL, stub canvas (a GPU-less honest box with fonts)' => [self::layoutClaims($differ, true, 0, $noGl, true), false],
            'a named font resolves to something else' => [self::layoutClaims($same, false, 0, $noGl, true), false],
            'per-font metrics found differences' => [self::layoutClaims($same, true, 21, $noGl, true), false],
            'per-font metrics unavailable' => [self::layoutClaims($same, true, null, $noGl, true), false],
            'GPU probe unavailable is not "no GL"' => [self::layoutClaims($same, true, 0, ['state' => 'unavailable'], false), false],
        ];
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    #[Test]
    #[DataProvider('layoutCases')]
    public function the_stub_rule_needs_font_independent_text_and_a_missing_drawing_surface(array $claims, bool $expected): void
    {
        $codes = array_column((new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult), 'code');

        $this->assertSame($expected, in_array('render_surfaces_stubbed', $codes, true));
    }

    #[Test]
    public function the_stub_rule_and_the_stub_canvas_are_one_root_cause_below_the_block_band(): void
    {
        $this->assertSame(CheckRegistry::evidenceGroupOf('canvas_winding_false'), CheckRegistry::evidenceGroupOf('render_surfaces_stubbed'));
        $this->assertNotSame(CheckRegistry::evidenceGroupOf('media_hover_unanswered'), CheckRegistry::evidenceGroupOf('render_surfaces_stubbed'));

        $together = CheckRegistry::effectiveWeight([
            ['code' => 'render_surfaces_stubbed', 'weight' => 30],
            ['code' => 'canvas_winding_false', 'weight' => 25],
        ]);
        $this->assertSame(30, $together);
        $this->assertLessThanOrEqual(EnvironmentConsistency::MAX_WEIGHT, $together);
    }

    #[Test]
    public function the_rule_is_registered_with_a_matching_weight_and_a_description(): void
    {
        $code = 'render_surfaces_stubbed';
        $this->assertTrue(CheckRegistry::isKnown($code));
        $this->assertSame('environment', CheckRegistry::familyOf($code));
        $this->assertSame(EnvironmentConsistency::weights()[$code], CheckRegistry::describe()[$code]['default_weight']);
        $this->assertNotSame('', trim((string) CheckRegistry::descriptionOf($code)));
    }
}

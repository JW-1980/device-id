<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\CheckRegistry;
use DeviceId\Keys\DeviceComponents;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The rules and trust projections added with probe set 4: automation marks and the headless
 * shell geometry, the canvas pattern, the device-hint headers, and the Brave / Firefox private
 * mode component lists. Each rule has a firing case, a silent honest-traffic case and, because
 * every detail is static prose, a check that no client-supplied string reaches it.
 */
final class NewSignalRulesTest extends TestCase
{
    private const WINDOWS_CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

    /** A marker no honest value contains; it must never come back in a detail. */
    private const MARKER = 'ZQX-CLIENT-STRING-7731';

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
     * @param  array<string, mixed>  $claims
     * @param  array<string, string>  $witnesses
     * @return array<string, string> code => detail
     */
    private static function fired(array $claims, array $witnesses = []): array
    {
        $out = [];
        foreach ((new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult([], $witnesses)) as $hit) {
            $out[$hit['code']] = $hit['detail'];
        }

        return $out;
    }

    /**
     * @param  array<string, mixed>  $integrity  integrity.data entries
     * @param  array<string, mixed>  $identity
     * @param  array<string, mixed>  $marks  the engineIdentity block
     * @return array<string, mixed>
     */
    private static function claims(array $integrity = [], array $identity = [], array $marks = ['engine' => 'v8', 'errorOwnProps' => 'message,stack', 'stackShape' => 'at', 'internalError' => false], string $userAgent = self::WINDOWS_CHROME): array
    {
        return [
            'tier1' => [
                'environment' => ['state' => 'ok', 'value' => [
                    'identity' => ['userAgent' => $userAgent, 'platform' => 'Win32'] + $identity,
                    'viewport' => ['innerWidth' => 1280, 'devicePixelRatio' => 1.5],
                ]],
                'engineIdentity' => ['state' => 'ok', 'value' => $marks],
            ],
            'integrity' => ['findings' => [], 'data' => $integrity],
        ];
    }

    // ---------------------------------------------------------------- automation marks

    #[Test]
    public function an_automation_global_fires_and_a_clean_window_is_silent(): void
    {
        $dirty = self::claims(['automationMarks' => ['state' => 'ok', 'value' => ['globals' => 1, 'cdc' => true, 'pw' => false, 'outerEqualsInner' => false, 'historyLength' => 3]]]);
        $clean = self::claims(['automationMarks' => ['state' => 'ok', 'value' => ['globals' => 0, 'cdc' => false, 'pw' => false, 'outerEqualsInner' => false, 'historyLength' => 3]]]);

        $this->assertArrayHasKey('automation_global_present', self::fired($dirty));
        $this->assertArrayNotHasKey('automation_global_present', self::fired($clean));
        $this->assertSame(30, EnvironmentConsistency::weights()['automation_global_present']);
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string, 2: bool}>
     */
    public static function geometryCases(): array
    {
        $chromium = ['engine' => 'v8', 'errorOwnProps' => 'message,stack', 'stackShape' => 'at', 'internalError' => false];
        $webkit = ['engine' => 'jsc', 'errorOwnProps' => 'message,line,column,sourceURL,stack', 'stackShape' => 'at-sign', 'internalError' => false];

        return [
            'headless Chromium on Windows' => [$chromium, self::WINDOWS_CHROME, true],
            'WebKit sets outer = inner by itself (Safari advanced protection)' => [$webkit, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15', false],
            'an Android UA is not a desktop window' => [$chromium, 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36', false],
        ];
    }

    /**
     * @param  array<string, mixed>  $marks
     */
    #[Test]
    #[DataProvider('geometryCases')]
    public function the_headless_shell_geometry_is_gated_on_engine_and_operating_system(array $marks, string $userAgent, bool $expected): void
    {
        $geometry = ['globals' => 0, 'cdc' => false, 'pw' => false, 'outerEqualsInner' => true, 'historyLength' => 1];
        $codes = self::fired(self::claims(['automationMarks' => ['state' => 'ok', 'value' => $geometry]], [], $marks, $userAgent));

        $this->assertSame($expected, array_key_exists('headless_shell_geometry', $codes));
    }

    #[Test]
    public function a_windowed_browser_or_a_longer_history_is_not_a_headless_shell(): void
    {
        foreach ([['outerEqualsInner' => false, 'historyLength' => 1], ['outerEqualsInner' => true, 'historyLength' => 4], ['outerEqualsInner' => null, 'historyLength' => 1]] as $shape) {
            $claims = self::claims(['automationMarks' => ['state' => 'ok', 'value' => ['globals' => 0, 'cdc' => false, 'pw' => false] + $shape]]);

            $this->assertArrayNotHasKey('headless_shell_geometry', self::fired($claims), json_encode($shape, JSON_THROW_ON_ERROR));
        }
        $this->assertSame(8, EnvironmentConsistency::weights()['headless_shell_geometry']);
    }

    // ---------------------------------------------------------------- canvas pattern

    #[Test]
    public function a_noised_canvas_pattern_fires_at_weight_four_and_silences_the_realm_comparison(): void
    {
        $noised = self::claims(['canvasPattern' => ['state' => 'ok', 'value' => ['exact' => false, 'deviations' => 12, 'stable' => true]]]);
        $exact = self::claims(['canvasPattern' => ['state' => 'ok', 'value' => ['exact' => true, 'deviations' => 0, 'stable' => true]]]);

        $this->assertArrayHasKey('canvas_pattern_perturbed', self::fired($noised));
        $this->assertArrayNotHasKey('canvas_pattern_perturbed', self::fired($exact));
        $this->assertSame(4, EnvironmentConsistency::weights()['canvas_pattern_perturbed']);

        // The same honest visitor must not also be scored by the page/worker canvas comparison.
        $split = ['tier2' => ['workerScope' => ['state' => 'ok', 'value' => ['window' => ['canvasHash' => 'aaaaaaaa'], 'worker' => ['canvasHash' => 'bbbbbbbb']]]]];
        $this->assertArrayHasKey('canvas_realm_mismatch', self::fired(array_merge_recursive($exact, $split)));
        $this->assertArrayNotHasKey('canvas_realm_mismatch', self::fired(array_merge_recursive($noised, $split)));
    }

    // ---------------------------------------------------------------- device hint headers

    #[Test]
    public function every_device_hint_matching_its_claim_is_silent(): void
    {
        $claims = self::claims([], ['deviceMemory' => 8, 'maxTouchPoints' => 0]);
        $claims['tier1']['uaClientHints'] = ['state' => 'ok', 'value' => ['high' => ['bitness' => '64', 'model' => '']]];
        $codes = self::fired($claims, [
            'sec_ch_device_memory' => '8',
            'sec_ch_dpr' => '1.5',
            'sec_ch_viewport_width' => '1263',
            'sec_ch_ua_bitness' => '"64"',
            'sec_ch_ua_model' => '""',
        ]);

        foreach (['device_memory_vs_ch', 'dpr_vs_ch', 'viewport_vs_ch', 'ch_bitness_vs_js', 'ch_model_vs_js'] as $code) {
            $this->assertArrayNotHasKey($code, $codes, $code);
        }
    }

    #[Test]
    public function a_page_level_spoof_that_the_headers_contradict_fires_each_rule(): void
    {
        $claims = self::claims([], ['deviceMemory' => 4, 'maxTouchPoints' => 0]);
        $claims['tier1']['uaClientHints'] = ['state' => 'ok', 'value' => ['high' => ['bitness' => '32', 'model' => 'Pixel 8']]];
        $codes = self::fired($claims, [
            'sec_ch_device_memory' => '8',
            'sec_ch_dpr' => '2',
            'sec_ch_viewport_width' => '1920',
            'sec_ch_ua_bitness' => '"64"',
            'sec_ch_ua_model' => '""',
        ]);

        foreach (['device_memory_vs_ch', 'dpr_vs_ch', 'viewport_vs_ch', 'ch_bitness_vs_js', 'ch_model_vs_js'] as $code) {
            $this->assertArrayHasKey($code, $codes, $code);
        }
    }

    #[Test]
    public function absent_or_unparseable_headers_are_silence_not_evidence(): void
    {
        $claims = self::claims([], ['deviceMemory' => 4, 'maxTouchPoints' => 0]);
        $claims['tier1']['uaClientHints'] = ['state' => 'ok', 'value' => ['high' => ['bitness' => '64', 'model' => 'x']]];

        $absent = self::fired($claims);
        $garbage = self::fired($claims, ['sec_ch_device_memory' => 'lots', 'sec_ch_dpr' => '', 'sec_ch_viewport_width' => 'wide']);

        foreach (['device_memory_vs_ch', 'dpr_vs_ch', 'viewport_vs_ch', 'ch_bitness_vs_js', 'ch_model_vs_js'] as $code) {
            $this->assertArrayNotHasKey($code, $absent, $code);
            $this->assertArrayNotHasKey($code, $garbage, $code);
        }
    }

    #[Test]
    public function the_viewport_header_tolerates_a_scrollbar_and_is_silent_on_touch_devices(): void
    {
        $claims = self::claims([], ['maxTouchPoints' => 0]);
        $this->assertArrayNotHasKey('viewport_vs_ch', self::fired($claims, ['sec_ch_viewport_width' => '1263']), 'a 17 px classic scrollbar');

        $touch = self::claims([], ['maxTouchPoints' => 5]);
        $this->assertArrayNotHasKey('viewport_vs_ch', self::fired($touch, ['sec_ch_viewport_width' => '600']), 'pinch-zoom moves innerWidth on touch devices');
        $this->assertArrayNotHasKey('viewport_vs_ch', self::fired($claims, ['sec_ch_viewport_width' => '600', 'sec_ch_ua_mobile' => '?1']));
        $this->assertArrayHasKey('viewport_vs_ch', self::fired($claims, ['sec_ch_viewport_width' => '600']));
    }

    // ---------------------------------------------------------------- details and weights

    #[Test]
    public function no_new_rule_puts_a_client_string_in_its_detail(): void
    {
        $claims = self::claims(
            [
                'automationMarks' => ['state' => 'ok', 'value' => ['globals' => 2, 'cdc' => true, 'pw' => true, 'outerEqualsInner' => true, 'historyLength' => 1, 'name' => self::MARKER]],
                'canvasPattern' => ['state' => 'ok', 'value' => ['exact' => false, 'deviations' => 3, 'stable' => true, 'note' => self::MARKER]],
            ],
            ['deviceMemory' => 4, 'maxTouchPoints' => 0, 'vendor' => self::MARKER],
        );
        $claims['tier1']['uaClientHints'] = ['state' => 'ok', 'value' => ['high' => ['bitness' => self::MARKER, 'model' => self::MARKER]]];

        $fired = self::fired($claims, [
            'sec_ch_device_memory' => '8', 'sec_ch_dpr' => '3', 'sec_ch_viewport_width' => '9000',
            'sec_ch_ua_bitness' => '"'.self::MARKER.'x"', 'sec_ch_ua_model' => '"'.self::MARKER.'y"',
        ]);

        $new = ['automation_global_present', 'headless_shell_geometry', 'canvas_pattern_perturbed', 'device_memory_vs_ch', 'dpr_vs_ch', 'viewport_vs_ch', 'ch_bitness_vs_js', 'ch_model_vs_js'];
        foreach ($new as $code) {
            $this->assertArrayHasKey($code, $fired, $code.' should fire in this fixture');
            $this->assertStringNotContainsString(self::MARKER, $fired[$code], $code);
        }
    }

    #[Test]
    public function the_new_rules_are_registered_and_no_single_check_can_block(): void
    {
        $new = ['automation_global_present' => 30, 'headless_shell_geometry' => 8, 'canvas_pattern_perturbed' => 4, 'device_memory_vs_ch' => 15, 'ch_bitness_vs_js' => 15, 'ch_model_vs_js' => 15, 'dpr_vs_ch' => 8, 'viewport_vs_ch' => 6, 'lie_battery_privacy_tool' => 15];
        foreach ($new as $code => $weight) {
            $this->assertSame($weight, EnvironmentConsistency::weights()[$code], $code);
            $this->assertSame($weight, CheckRegistry::describe()[$code]['default_weight'], $code);
            $this->assertContains($code, (new EnvironmentConsistency)->ruleCodes(), $code);
        }
        $this->assertLessThanOrEqual(45, max(EnvironmentConsistency::weights()));
    }

    // ---------------------------------------------------------------- trust projection

    /**
     * @param  array<string, mixed>  $resistance
     * @param  array<string, mixed>  $marks
     * @return list<string>
     */
    private static function untrusted(array $resistance, array $integrity = [], array $marks = ['engine' => 'v8', 'errorOwnProps' => 'message,stack', 'stackShape' => 'at', 'internalError' => false], string $userAgent = self::WINDOWS_CHROME): array
    {
        $claims = self::claims(['resistance' => ['state' => 'ok', 'value' => $resistance]] + $integrity, [], $marks, $userAgent);

        $out = DeviceComponents::untrusted($claims);
        sort($out);

        return $out;
    }

    #[Test]
    public function brave_makes_the_farbled_components_untrusted_and_stock_chromium_does_not(): void
    {
        $brave = self::untrusted(['brave' => true, 'rfp' => false, 'tor' => false, 'gecko' => false]);
        $stock = self::untrusted(['brave' => false, 'rfp' => false, 'tor' => false, 'gecko' => false]);

        foreach (['cores', 'memory', 'voices', 'panel', 'aspect', 'fonts', 'emoji', 'gpu', 'gpuMath'] as $component) {
            $this->assertContains($component, $brave, $component);
        }
        $this->assertSame([], $stock);
    }

    #[Test]
    public function a_brave_flag_on_a_gecko_user_agent_is_not_honoured(): void
    {
        $firefoxMarks = ['engine' => 'spidermonkey', 'errorOwnProps' => 'fileName,lineNumber,columnNumber,message,stack', 'stackShape' => 'at-sign', 'internalError' => true];
        $firefox = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';

        $this->assertSame([], self::untrusted(['brave' => true, 'rfp' => false, 'tor' => false, 'gecko' => true], [], $firefoxMarks, $firefox));
    }

    #[Test]
    public function a_noised_pattern_on_a_gecko_without_rfp_marks_the_core_count_and_the_gpu_read_back_untrusted(): void
    {
        $firefoxMarks = ['engine' => 'spidermonkey', 'errorOwnProps' => 'fileName,lineNumber,columnNumber,message,stack', 'stackShape' => 'at-sign', 'internalError' => true];
        $firefox = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';
        $noised = ['canvasPattern' => ['state' => 'ok', 'value' => ['exact' => false, 'deviations' => 40, 'stable' => true]]];
        $exact = ['canvasPattern' => ['state' => 'ok', 'value' => ['exact' => true, 'deviations' => 0, 'stable' => true]]];
        $plain = ['brave' => false, 'rfp' => false, 'tor' => false, 'gecko' => true];

        $private = self::untrusted($plain, $noised, $firefoxMarks, $firefox);
        foreach (['cores', 'fonts', 'emoji', 'scripts', 'fontsCount', 'gpuMath'] as $component) {
            $this->assertContains($component, $private, $component);
        }
        $this->assertSame([], self::untrusted($plain, $exact, $firefoxMarks, $firefox), 'an ordinary Firefox keeps its core count');

        // The same pattern on Chromium touches the canvas-measured components but not the core count.
        $chromium = self::untrusted(['brave' => false, 'rfp' => false, 'tor' => false, 'gecko' => false], $noised);
        $this->assertNotContains('cores', $chromium);
        $this->assertContains('fonts', $chromium);
    }

    #[Test]
    public function rfp_also_drops_the_pinned_sample_rate(): void
    {
        $this->assertContains('audio', DeviceComponents::PROTECTED_UNTRUSTED);
    }

    // ---------------------------------------------------------------- gpu realm comparison

    /**
     * @return array<string, mixed>
     */
    private static function gpuRealms(?string $page, ?string $worker, string $pagePrecision = 'highp:23', string $workerPrecision = 'highp:23'): array
    {
        return ['tier2' => ['workerScope' => ['state' => 'ok', 'value' => [
            'window' => ['gpuMathHash' => $page, 'gpuMathPrecision' => $pagePrecision],
            'worker' => ['gpuMathHash' => $worker, 'gpuMathPrecision' => $workerPrecision],
        ]]]];
    }

    #[Test]
    public function a_page_render_that_differs_from_the_workers_fires_and_agreeing_or_missing_renders_do_not(): void
    {
        $this->assertArrayHasKey('gpu_realm_mismatch', self::fired(self::gpuRealms('aaaaaaaa', 'bbbbbbbb')));

        $this->assertArrayNotHasKey('gpu_realm_mismatch', self::fired(self::gpuRealms('aaaaaaaa', 'aaaaaaaa')));
        $this->assertArrayNotHasKey('gpu_realm_mismatch', self::fired(self::gpuRealms('aaaaaaaa', null)), 'a worker without WebGL says nothing');
        $this->assertArrayNotHasKey('gpu_realm_mismatch', self::fired(self::gpuRealms(null, 'bbbbbbbb')));
        $this->assertArrayNotHasKey('gpu_realm_mismatch', self::fired(self::gpuRealms('aaaaaaaa', 'bbbbbbbb', 'highp:23', 'mediump:10')), 'hashes of different precision classes never compare');
        $this->assertSame(4, EnvironmentConsistency::weights()['gpu_realm_mismatch']);
    }

    #[Test]
    public function the_gpu_realm_comparison_stays_silent_for_a_noised_read_back_that_is_already_scored(): void
    {
        $split = self::gpuRealms('aaaaaaaa', 'bbbbbbbb');
        $noised = array_merge_recursive(self::claims(['canvasPattern' => ['state' => 'ok', 'value' => ['exact' => false, 'deviations' => 3, 'stable' => true]]]), $split);
        $brave = array_merge_recursive(self::claims(['resistance' => ['state' => 'ok', 'value' => ['brave' => true, 'rfp' => false, 'tor' => false]]]), $split);

        $this->assertArrayNotHasKey('gpu_realm_mismatch', self::fired($noised));
        $this->assertArrayNotHasKey('gpu_realm_mismatch', self::fired($brave));
        // A forged Brave flag on a Gecko engine buys nothing: the marks refute it.
        $forged = array_merge_recursive(self::claims(
            ['resistance' => ['state' => 'ok', 'value' => ['brave' => true, 'rfp' => false, 'tor' => false]]],
            [],
            ['engine' => 'spidermonkey', 'errorOwnProps' => 'fileName,lineNumber,columnNumber', 'stackShape' => 'at-sign', 'internalError' => true],
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0',
        ), $split);
        $this->assertArrayHasKey('gpu_realm_mismatch', self::fired($forged));
    }

    #[Test]
    public function a_page_whose_read_back_disagrees_with_its_worker_offers_no_gpu_math_component(): void
    {
        $this->assertContains('gpuMath', DeviceComponents::untrusted(array_merge_recursive(self::claims(), self::gpuRealms('aaaaaaaa', 'bbbbbbbb'))));
        $this->assertNotContains('gpuMath', DeviceComponents::untrusted(array_merge_recursive(self::claims(), self::gpuRealms('aaaaaaaa', 'aaaaaaaa'))));
    }
}

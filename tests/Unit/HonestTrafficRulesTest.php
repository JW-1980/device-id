<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\Rules\EnvironmentConsistency;
use NutriCompare\Fingerprint\Support\Config;
use NutriCompare\Fingerprint\Support\TransportIntegrityResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * False-positive regressions (research section 2): each rule here fired on a population of
 * honest browsers. Every case pairs the honest shape (silent) with the real spoof that must
 * still fire, so a fix cannot be "turn the rule off".
 *
 * The honest shapes are derived from browser behaviour, not captured traffic (the fixtures
 * are all desktop Linux Chromium/Firefox/WebKit); each docblock names its source and where it
 * is unverified on hardware.
 */
final class HonestTrafficRulesTest extends TestCase
{
    private const DESKTOP_CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

    private const ANDROID_CHROME = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36';

    private const CHROMEOS = 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

    private const ARM_LINUX = 'Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

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
     * @return list<string>
     */
    private static function codes(array $claims, array $witnesses = []): array
    {
        $contradictions = (new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult([], $witnesses));

        return array_map(static fn (array $contradiction): string => $contradiction['code'], $contradictions);
    }

    /**
     * @param  array<string, mixed>  $identity
     * @param  array<string, mixed>  $plugins
     * @return array<string, mixed>
     */
    private static function environment(string $userAgent, string $platform, array $identity = [], array $plugins = ['length' => 5, 'names' => []]): array
    {
        return ['tier1' => ['environment' => ['state' => 'ok', 'value' => [
            'identity' => ['userAgent' => $userAgent, 'platform' => $platform] + $identity,
            'plugins' => $plugins,
        ]]]];
    }

    // ---------------------------------------------------------------- plugins_vs_ua

    #[Test]
    public function android_chrome_with_no_plugin_list_is_not_a_finding(): void
    {
        $claims = self::environment(self::ANDROID_CHROME, 'Linux armv8l', ['pdfViewerEnabled' => false], ['length' => 0, 'names' => []]);

        $this->assertNotContains('plugins_vs_ua', self::codes($claims));
    }

    #[Test]
    public function desktop_chrome_with_the_pdf_viewer_disabled_is_not_a_finding(): void
    {
        $claims = self::environment(self::DESKTOP_CHROME, 'Win32', ['pdfViewerEnabled' => false], ['length' => 0, 'names' => []]);

        $this->assertNotContains('plugins_vs_ua', self::codes($claims));
    }

    #[Test]
    public function desktop_chrome_claiming_a_pdf_viewer_but_listing_no_plugins_still_fires(): void
    {
        foreach ([true, null] as $viewer) {
            $claims = self::environment(self::DESKTOP_CHROME, 'Win32', $viewer === null ? [] : ['pdfViewerEnabled' => $viewer], ['length' => 0, 'names' => []]);

            $this->assertContains('plugins_vs_ua', self::codes($claims), 'pdfViewerEnabled='.var_export($viewer, true));
        }
    }

    // ---------------------------------------------------------------- lied_os

    #[Test]
    public function a_chromebook_is_not_a_lied_os(): void
    {
        // ChromeOS: UA `CrOS`, navigator.platform `Linux x86_64` (and `CrOS x86_64` on older
        // builds), Sec-CH-UA-Platform `"Chrome OS"`.
        foreach (['Linux x86_64', 'CrOS x86_64'] as $platform) {
            $codes = self::codes(self::environment(self::CHROMEOS, $platform), ['sec_ch_ua_platform' => '"Chrome OS"']);

            $this->assertNotContains('lied_os', $codes, $platform);
        }
    }

    #[Test]
    public function linux_on_arm_is_not_a_lied_os(): void
    {
        // Raspberry Pi OS, Asahi: platform `Linux aarch64`, Sec-CH-UA-Platform `"Linux"`.
        $codes = self::codes(self::environment(self::ARM_LINUX, 'Linux aarch64'), ['sec_ch_ua_platform' => '"Linux"']);

        $this->assertNotContains('lied_os', $codes);
    }

    #[Test]
    public function android_on_arm_is_still_consistent_and_a_desktop_claim_on_arm_still_fires(): void
    {
        $android = self::codes(self::environment(self::ANDROID_CHROME, 'Linux armv8l'), ['sec_ch_ua_platform' => '"Android"']);
        $this->assertNotContains('lied_os', $android);

        // A Windows UA over an ARM Linux platform is a real contradiction.
        $this->assertContains('lied_os', self::codes(self::environment(self::DESKTOP_CHROME, 'Linux aarch64')));
        // So is a Windows UA over a Linux platform, and a Chromebook whose header says Windows.
        $this->assertContains('lied_os', self::codes(self::environment(self::DESKTOP_CHROME, 'Linux x86_64')));
        $this->assertContains('lied_os', self::codes(self::environment(self::CHROMEOS, 'Linux x86_64'), ['sec_ch_ua_platform' => '"Windows"']));
    }

    // ---------------------------------------------------------------- ua_vs_ch_major

    /**
     * @return array<string, array{0: string, 1: string, 2: list<array{brand: string, version: string}>}>
     */
    public static function chromiumDerivatives(): array
    {
        return [
            'Opera (Chromium version in uaFullVersion)' => [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 OPR/125.0.0.0',
                '141.0.7390.1',
                [['brand' => 'Opera', 'version' => '125.0.5000.1'], ['brand' => 'Chromium', 'version' => '141.0.7390.1'], ['brand' => 'Not A Brand', 'version' => '24.0.0.0']],
            ],
            'Opera' => [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 OPR/125.0.0.0',
                '125.0.5000.1',
                [['brand' => 'Opera', 'version' => '125.0.5000.1'], ['brand' => 'Chromium', 'version' => '141.0.7390.1'], ['brand' => 'Not A Brand', 'version' => '24.0.0.0']],
            ],
            'Samsung Internet' => [
                'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/141.0.0.0 Mobile Safari/537.36',
                '27.0.1.1',
                [['brand' => 'Samsung Internet', 'version' => '27.0.1.1'], ['brand' => 'Chromium', 'version' => '141.0.7390.1'], ['brand' => 'Not A Brand', 'version' => '24.0.0.0']],
            ],
        ];
    }

    /**
     * @param  list<array{brand: string, version: string}>  $list
     */
    #[Test]
    #[DataProvider('chromiumDerivatives')]
    public function a_chromium_derivative_with_its_own_full_version_is_not_a_finding(string $userAgent, string $uaFullVersion, array $list): void
    {
        $claims = self::environment($userAgent, 'Win32') + ['tier1' => []];
        $claims['tier1']['environment'] = self::environment($userAgent, 'Win32')['tier1']['environment'];
        $claims['tier1']['uaClientHints'] = ['state' => 'ok', 'value' => ['high' => ['uaFullVersion' => $uaFullVersion, 'fullVersionList' => $list]]];

        $this->assertNotContains('ua_vs_ch_major', self::codes($claims));
    }

    #[Test]
    public function a_copied_chrome_user_agent_over_the_real_version_list_still_fires(): void
    {
        $claims = self::environment(str_replace('Chrome/141', 'Chrome/112', self::DESKTOP_CHROME), 'Win32');
        $claims['tier1']['uaClientHints'] = ['state' => 'ok', 'value' => ['high' => [
            'uaFullVersion' => '141.0.7390.1',
            'fullVersionList' => [['brand' => 'Chromium', 'version' => '141.0.7390.1'], ['brand' => 'Not A Brand', 'version' => '24.0.0.0']],
        ]]];

        $this->assertContains('ua_vs_ch_major', self::codes($claims));
    }

    #[Test]
    public function a_chrome_without_a_version_list_is_still_judged_by_uafullversion(): void
    {
        $claims = self::environment(str_replace('Chrome/141', 'Chrome/112', self::DESKTOP_CHROME), 'Win32');
        $claims['tier1']['uaClientHints'] = ['state' => 'ok', 'value' => ['high' => ['uaFullVersion' => '141.0.7390.1']]];

        $this->assertContains('ua_vs_ch_major', self::codes($claims));
    }

    // ---------------------------------------------------------------- screen_vs_css_media

    /**
     * @return array<string, mixed>
     */
    private static function screenDisagreeing(bool $brave, string $engineStack = 'at'): array
    {
        return [
            'tier1' => [
                'environment' => ['state' => 'ok', 'value' => ['identity' => ['userAgent' => self::DESKTOP_CHROME, 'platform' => 'Win32']]],
                'engineIdentity' => ['state' => 'ok', 'value' => ['engine' => 'v8', 'errorOwnProps' => 'message,stack', 'stackShape' => $engineStack, 'internalError' => false]],
            ],
            'integrity' => ['data' => [
                'phantomRealm' => ['state' => 'ok', 'value' => ['screenTruth' => ['cssWidth' => false, 'cssHeight' => false]]],
                'resistance' => ['state' => 'ok', 'value' => ['brave' => $brave, 'rfp' => false, 'tor' => false]],
            ]],
        ];
    }

    #[Test]
    public function brave_snapping_the_screen_is_not_a_finding(): void
    {
        // Brave Balanced snaps `screen` to 7 sizes while CSS device-width tracks the viewport.
        $this->assertNotContains('screen_vs_css_media', self::codes(self::screenDisagreeing(brave: true)));
    }

    #[Test]
    public function an_overridden_screen_on_a_chromium_without_the_brave_shield_still_fires(): void
    {
        $this->assertContains('screen_vs_css_media', self::codes(self::screenDisagreeing(brave: false)));
    }

    #[Test]
    public function a_brave_flag_without_chromium_engine_evidence_does_not_buy_silence(): void
    {
        // The flag is client-reported; the engine marks of a Gecko stack refute it.
        $claims = self::screenDisagreeing(brave: true);
        $claims['tier1']['engineIdentity']['value'] = ['engine' => 'spidermonkey', 'errorOwnProps' => 'fileName,lineNumber,columnNumber', 'stackShape' => 'at-sign', 'internalError' => true];

        $this->assertContains('screen_vs_css_media', self::codes($claims));
    }

    // ---------------------------------------------------------------- gpu_webgpu_vs_webgl

    /**
     * @return array<string, mixed>
     */
    private static function gpuPair(string $webgpuVendor, string $webglRenderer): array
    {
        return ['tier2' => ['gpu' => ['state' => 'ok', 'value' => [
            'webgpu' => ['vendor' => $webgpuVendor],
            'webgl' => ['renderer' => $webglRenderer, 'model' => strtolower($webglRenderer)],
        ]]]];
    }

    #[Test]
    public function a_hybrid_graphics_laptop_is_not_a_finding(): void
    {
        // Integrated + discrete GPU: requestAdapter() and the default WebGL context may pick
        // different ones. Intel, AMD and NVIDIA are the vendors that ship in hybrid pairs.
        foreach ([['nvidia', 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
            ['intel', 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)'],
            ['amd', 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
            ['nvidia', 'ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)']] as [$vendor, $renderer]) {
            $this->assertNotContains('gpu_webgpu_vs_webgl', self::codes(self::gpuPair($vendor, $renderer)), "{$vendor} / {$renderer}");
        }
    }

    #[Test]
    public function an_apple_gpu_over_a_desktop_pc_renderer_still_fires(): void
    {
        $this->assertContains('gpu_webgpu_vs_webgl', self::codes(self::gpuPair('apple', 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)')));
        $this->assertContains('gpu_webgpu_vs_webgl', self::codes(self::gpuPair('nvidia', 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)')));
        $this->assertContains('gpu_webgpu_vs_webgl', self::codes(self::gpuPair('qualcomm', 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)')));
    }

    // ---------------------------------------------------------------- lie_battery_*

    /**
     * A claim set where the lie battery caught `$lied` and the worker disagrees with the page
     * about the User-Agent: the footprint of an extension that patches the page realm only.
     *
     * @param  list<string>  $lied
     * @param  array<string, mixed>  $extraIntegrity
     * @return array<string, mixed>
     */
    private static function lieBatteryClaims(array $lied, bool $workerDisagrees, array $extraIntegrity = []): array
    {
        $window = ['userAgent' => self::DESKTOP_CHROME, 'platform' => 'Win32', 'hardwareConcurrency' => 8, 'timeZone' => 'Europe/Amsterdam', 'tzOffset' => -60];
        $worker = $workerDisagrees ? ['userAgent' => str_replace('Windows NT 10.0; Win64; x64', 'X11; Linux x86_64', self::DESKTOP_CHROME)] + $window : $window;

        return [
            'tier1' => ['environment' => ['state' => 'ok', 'value' => ['identity' => ['userAgent' => self::DESKTOP_CHROME, 'platform' => 'Win32']]]],
            'tier2' => ['workerScope' => ['state' => 'ok', 'value' => ['window' => $window, 'worker' => $worker]]],
            'integrity' => ['findings' => [['code' => 'lie_battery_failed']], 'data' => [
                'lieBattery' => ['state' => 'ok', 'value' => ['checked' => 28, 'lied' => array_fill_keys($lied, ['proto_cycle'])]],
            ] + $extraIntegrity],
        ];
    }

    #[Test]
    public function a_page_only_navigator_wrapper_is_a_privacy_tool_not_an_identity_lie(): void
    {
        // JShelter / a User-Agent switcher: wraps Navigator getters in the page realm only, and
        // trips no other conformance check.
        $codes = self::codes(self::lieBatteryClaims(['Navigator.userAgent', 'Navigator.hardwareConcurrency'], workerDisagrees: true));

        $this->assertContains('lie_battery_privacy_tool', $codes);
        $this->assertNotContains('lie_battery_failed', $codes);
        $this->assertSame(15, EnvironmentConsistency::weights()['lie_battery_privacy_tool']);
    }

    #[Test]
    public function the_same_lie_in_both_realms_stays_an_identity_lie(): void
    {
        $codes = self::codes(self::lieBatteryClaims(['Navigator.userAgent'], workerDisagrees: false));

        $this->assertContains('lie_battery_failed', $codes);
        $this->assertNotContains('lie_battery_privacy_tool', $codes);
    }

    #[Test]
    public function a_wrapper_that_also_hides_itself_stays_an_identity_lie(): void
    {
        // A stealth spoofer patches Function.prototype.toString as well; the fresh realm sees it.
        $claims = self::lieBatteryClaims(['Navigator.userAgent'], workerDisagrees: true, extraIntegrity: [
            'phantomRealm' => ['state' => 'ok', 'value' => ['nativeToString' => ['checked' => 28, 'mismatched' => ['Navigator.userAgent']]]],
        ]);

        $codes = self::codes($claims);
        $this->assertContains('lie_battery_failed', $codes);
        $this->assertNotContains('lie_battery_privacy_tool', $codes);

        // So does a closure getter, which a wrong-receiver call exposes.
        $claims = self::lieBatteryClaims(['Navigator.userAgent'], workerDisagrees: true);
        $claims['integrity']['findings'][] = ['code' => 'wrong_receiver_did_not_throw'];
        $this->assertContains('lie_battery_failed', self::codes($claims));
    }

    #[Test]
    public function a_hidden_webdriver_or_a_wrapped_non_privacy_surface_stays_an_identity_lie(): void
    {
        $this->assertContains('lie_battery_failed', self::codes(self::lieBatteryClaims(['Navigator.webdriver'], workerDisagrees: true)));
        $this->assertContains('lie_battery_failed', self::codes(self::lieBatteryClaims(['Navigator.userAgent', 'Permissions.query'], workerDisagrees: true)));
        $this->assertContains('lie_battery_failed', self::codes(self::lieBatteryClaims(['Math.sin'], workerDisagrees: true)));
    }
}

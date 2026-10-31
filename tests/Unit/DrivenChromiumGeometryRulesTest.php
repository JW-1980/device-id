<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\CheckRegistry;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../tools/capture/CaptureAnalysis.php';

/**
 * The three geometry rules the red-team run added (`viewport_fills_screen`, `headless_default_screen`,
 * `window_exceeds_screen`), on the claims of a real captured Chromium (the honest headed capture) with
 * only the window and screen numbers replaced. Each firing case is the geometry a measured tool produced
 * (`tests/Fixtures/fingerprint/redteam`, see RedteamFixturesTest); each silent case is a window an honest
 * desktop produces. The honest cases are derived from how browsers behave and are not measured on Windows
 * or macOS hardware (the harness machine is a Linux container): see the README "Red-team testing".
 */
final class DrivenChromiumGeometryRulesTest extends TestCase
{
    private const CODES = ['viewport_fills_screen', 'headless_default_screen', 'window_exceeds_screen'];

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
     * @param  array{screen?: array<string, int>, viewport?: array<string, int>, identity?: array<string, mixed>, capture?: string}  $change
     * @return list<string> the geometry codes that fire
     */
    private static function fired(array $change): array
    {
        $capture = $change['capture'] ?? 'linux-container.linux.chromium.headed.honest';
        $record = json_decode((string) file_get_contents(__DIR__.'/../Fixtures/fingerprint/captures/'.$capture.'.json'), true, 64, JSON_THROW_ON_ERROR);
        $claims = CaptureAnalysis::mergedClaims($record);
        foreach (['screen', 'viewport', 'identity'] as $group) {
            foreach ($change[$group] ?? [] as $field => $value) {
                $claims['tier1']['environment'][$group][$field] = $value;
            }
        }
        $transport = CaptureAnalysis::transport($record);
        $codes = array_map(
            static fn (array $c): string => $c['code'],
            (new EnvironmentConsistency)->contradictions($claims, $transport),
        );

        return array_values(array_intersect(self::CODES, $codes));
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function geometries(): array
    {
        $screen = static fn (int $w, int $h, ?int $availH = null): array => ['width' => $w, 'height' => $h, 'availWidth' => $w, 'availHeight' => $availH ?? $h];
        $window = static fn (int $iw, int $ih, int $ow, int $oh): array => ['innerWidth' => $iw, 'innerHeight' => $ih, 'outerWidth' => $ow, 'outerHeight' => $oh];

        return [
            // Measured tool output.
            'Playwright default viewport 1280x720 in a window with chrome (patchright, playwright-stealth)' => [['screen' => $screen(1280, 720), 'viewport' => $window(1280, 720, 1288, 805)], ['viewport_fills_screen']],
            'Puppeteer default viewport 800x600 (puppeteer-extra headless)' => [['screen' => $screen(800, 600), 'viewport' => $window(800, 600, 800, 685)], ['viewport_fills_screen', 'headless_default_screen']],
            'headless Chromium 800x600 screen, real window inside it (nodriver headless)' => [['screen' => $screen(800, 600), 'viewport' => $window(780, 493, 780, 580)], ['headless_default_screen']],
            'window larger than the screen in both dimensions (undetected-chromedriver headless)' => [['screen' => $screen(800, 600), 'viewport' => $window(1920, 937, 1920, 1080)], ['headless_default_screen', 'window_exceeds_screen']],

            // Honest windows: all silent.
            'ordinary window on a 1080p screen' => [['screen' => $screen(1920, 1080, 1040), 'viewport' => $window(1500, 800, 1516, 900)], []],
            'Windows maximised window (16 px invisible border on each axis)' => [['screen' => $screen(1920, 1080, 1040), 'viewport' => $window(1920, 937, 1936, 1056)], []],
            'fullscreen (F11): the viewport is the screen and there is no chrome around it' => [['screen' => $screen(1920, 1080), 'viewport' => $window(1920, 1080, 1920, 1080)], []],
            'window spanning two monitors: wider than the screen, not taller' => [['screen' => $screen(1920, 1080, 1040), 'viewport' => $window(3800, 900, 3840, 1000)], []],
            'a small 800x600 kiosk panel with a taskbar (available area smaller than the screen)' => [['screen' => $screen(800, 600, 560), 'viewport' => $window(780, 480, 800, 560)], []],
            'a phone or tablet whose viewport fills the screen (touch points)' => [['screen' => $screen(412, 915), 'viewport' => $window(412, 915, 412, 1000), 'identity' => ['maxTouchPoints' => 5]], []],
            'no outer size reported (in-app browsers)' => [['screen' => $screen(1280, 720), 'viewport' => $window(1280, 720, 0, 0)], []],
        ];
    }

    /**
     * @param  array<string, mixed>  $change
     * @param  list<string>  $expected
     */
    #[Test]
    #[DataProvider('geometries')]
    public function the_rules_fire_on_driven_geometry_and_stay_silent_on_honest_windows(array $change, array $expected): void
    {
        $this->assertSame($expected, self::fired($change));
    }

    #[Test]
    public function the_rules_read_desktop_chromium_only(): void
    {
        // The same Playwright geometry, but the capture is a Firefox or a WebKit: no verdict from these rules.
        $fillsScreen = ['screen' => ['width' => 1280, 'height' => 720, 'availWidth' => 1280, 'availHeight' => 720], 'viewport' => ['innerWidth' => 1280, 'innerHeight' => 720, 'outerWidth' => 1288, 'outerHeight' => 805]];
        $this->assertSame(['viewport_fills_screen'], self::fired($fillsScreen));
        $this->assertSame([], self::fired($fillsScreen + ['capture' => 'linux-container.linux.firefox.headed.automation']));
        $this->assertSame([], self::fired($fillsScreen + ['capture' => 'linux-container.linux.webkit.headed.automation']));
    }

    #[Test]
    public function the_weights_are_registered_small_and_none_blocks_alone(): void
    {
        foreach (self::CODES as $code) {
            $weight = EnvironmentConsistency::weights()[$code];
            $this->assertSame($weight, CheckRegistry::describe()[$code]['default_weight'], $code);
            $this->assertNotSame('', CheckRegistry::descriptionOf($code), $code);
            $this->assertLessThanOrEqual(45, $weight, $code);
            $this->assertLessThan(80, (int) round(100 * (1 - exp(-$weight / 40))), $code.' alone must stay below the block band');
        }
    }

    #[Test]
    public function no_honest_capture_fires_a_geometry_rule(): void
    {
        foreach (glob(__DIR__.'/../Fixtures/fingerprint/captures/*.json') ?: [] as $file) {
            $record = json_decode((string) file_get_contents($file), true, 64, JSON_THROW_ON_ERROR);
            if ($record['labels']['class'] !== 'honest') {
                continue;
            }
            $codes = array_keys(CaptureAnalysis::analyse($record)['merged']['codes']);
            $this->assertSame([], array_values(array_intersect(self::CODES, $codes)), basename($file));
        }
    }
}

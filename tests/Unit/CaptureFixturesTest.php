<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\Capture\Expectations;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../tools/capture/CaptureAnalysis.php';
require_once __DIR__.'/../../tools/capture/Expectations.php';

/**
 * The permanent honest-traffic regression suite: the engine over captures taken by
 * `npm run capture` with the REAL collector in real browsers (Playwright Chromium, Firefox and
 * WebKit on Linux, headless and headed under Xvfb), judged by `tools/capture/expectations.php`.
 *
 * The fixtures hold what the browser said (claims of both envelopes, request headers, labels),
 * never what the engine answered, so an engine change is re-evaluated against real browsers
 * rather than compared with a recording. Add captures from other machines with
 * `php tools/capture/engine-report.php <dir> --save-fixtures=tests/Fixtures/fingerprint/captures`.
 *
 * These are synthetic machines (a container, software GL, no user fonts), not real Windows or
 * Mac hardware; that gap is what running the harness on those machines closes.
 */
final class CaptureFixturesTest extends TestCase
{
    private const DIRECTORY = __DIR__.'/../Fixtures/fingerprint/captures';

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
    private static function load(string $id): array
    {
        $path = self::DIRECTORY.'/'.$id.'.json';
        self::assertFileExists($path);

        /** @var array<string, mixed> $record */
        $record = json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);

        return $record;
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function captures(): array
    {
        $files = glob(self::DIRECTORY.'/*.json') ?: [];
        sort($files);
        $out = [];
        foreach ($files as $file) {
            $id = basename($file, '.json');
            $out[$id] = [$id];
        }

        return $out;
    }

    #[Test]
    public function the_fixture_set_covers_every_class_and_engine(): void
    {
        $records = array_map(static fn (array $row): array => self::load($row[0]), array_values(self::captures()));

        $this->assertSame(['automation', 'headless', 'honest'], array_values(array_unique(array_map(static fn (array $r): string => $r['labels']['class'], $this->sorted($records)))));
        foreach (['chromium', 'firefox', 'webkit'] as $browser) {
            $this->assertNotEmpty(array_filter($records, static fn (array $r): bool => $r['browser']['name'] === $browser), "no {$browser} capture");
        }
        foreach ($records as $record) {
            $this->assertSame(CaptureAnalysis::DATASET_VERSION, $record['schema_version']);
            $this->assertNotNull($record['claims']['tier1']);
            $this->assertNotNull($record['claims']['tier2']);
        }
    }

    /**
     * @param  list<array<string, mixed>>  $records
     * @return list<array<string, mixed>>
     */
    private function sorted(array $records): array
    {
        usort($records, static fn (array $a, array $b): int => strcmp($a['labels']['class'], $b['labels']['class']));

        return $records;
    }

    #[Test]
    #[DataProvider('captures')]
    public function a_capture_meets_the_expectations(string $id): void
    {
        $record = self::load($id);

        $failures = Expectations::evaluate($record, CaptureAnalysis::analyse($record), Expectations::load());

        $this->assertSame([], array_column($failures, 'message'), "{$id} broke an expectation");
    }

    #[Test]
    public function an_honest_headed_chromium_is_clean_and_unpenalised(): void
    {
        $answer = CaptureAnalysis::analyse(self::load('linux-container.linux.chromium.headed.honest'))['merged'];

        $this->assertSame('pass', $answer['band']);
        $this->assertSame([], array_keys($answer['codes']));
        $this->assertSame([], $answer['confidence']['penalties']);
    }

    #[Test]
    public function a_headless_chromium_is_caught_by_its_user_agent_token(): void
    {
        $answer = CaptureAnalysis::analyse(self::load('linux-container.linux.chromium.headless.default'))['merged'];

        $this->assertArrayHasKey('ua_headless_token', $answer['codes']);
        // Four independent self-announcements (UA token, notification pair, shell geometry,
        // navigator.webdriver) are a block together; no single one of them is (max 45).
        $this->assertEqualsCanonicalizing(
            ['ua_headless_token', 'notification_permission_vs_query', 'headless_shell_geometry', 'webdriver_true'],
            array_keys($answer['codes']),
        );
        $this->assertSame('block', $answer['band']);
    }

    #[Test]
    public function a_driven_headless_chromium_is_caught_by_its_shell_geometry_and_webdriver_without_the_token(): void
    {
        $record = self::load('linux-container.linux.chromium.headless.default');
        /** @var array<string, mixed> $record */
        $record = json_decode(str_replace('HeadlessChrome', 'Chrome', (string) json_encode($record)), true, 64, JSON_THROW_ON_ERROR);

        $codes = array_keys(CaptureAnalysis::analyse($record)['merged']['codes']);

        $this->assertContains('headless_shell_geometry', $codes);
        $this->assertContains('webdriver_true', $codes);
        $this->assertNotContains('ua_headless_token', $codes);
    }

    #[Test]
    public function the_shell_geometry_rule_goes_blind_when_the_history_must_be_exactly_one(): void
    {
        // Negative control for the history fix: the captured driver tab has two entries.
        $record = self::load('linux-container.linux.chromium.headless.default');
        $marks = &$record['claims']['tier1']['integrity']['data']['automationMarks']['value'];
        $this->assertSame(2, $marks['historyLength'], 'the real Playwright tab starts on about:blank');
        $marks['historyLength'] = 3;
        // The client's own finding list carries the code too (the server unites both).
        foreach (['tier1', 'tier2'] as $slot) {
            $record['claims'][$slot]['integrity']['findings'] = array_values(array_filter(
                $record['claims'][$slot]['integrity']['findings'],
                static fn (array $finding): bool => $finding['code'] !== 'headless_shell_geometry',
            ));
        }

        $this->assertArrayNotHasKey('headless_shell_geometry', CaptureAnalysis::analyse($record)['merged']['codes']);
    }

    #[Test]
    public function a_driver_that_exposes_a_binding_leaves_a_global_and_one_that_does_not_leaves_none(): void
    {
        foreach (['chromium', 'firefox', 'webkit'] as $browser) {
            $instrumented = self::load("linux-container.linux.{$browser}.headless.instrumented");
            $plain = self::load("linux-container.linux.{$browser}.headless.default");

            $this->assertGreaterThan(0, $instrumented['claims']['tier1']['integrity']['data']['automationMarks']['value']['globals'], $browser);
            $this->assertTrue($instrumented['claims']['tier1']['integrity']['data']['automationMarks']['value']['pw'], $browser);
            $this->assertArrayHasKey('automation_global_present', CaptureAnalysis::analyse($instrumented)['merged']['codes'], $browser);

            $this->assertSame(0, $plain['claims']['tier1']['integrity']['data']['automationMarks']['value']['globals'], $browser);
            $this->assertArrayNotHasKey('automation_global_present', CaptureAnalysis::analyse($plain)['merged']['codes'], $browser);
        }
    }

    #[Test]
    public function headless_firefox_is_caught_by_its_virtual_screen_and_a_headed_one_is_not(): void
    {
        $headless = CaptureAnalysis::analyse(self::load('linux-container.linux.firefox.headless.default'))['merged'];
        $headed = CaptureAnalysis::analyse(self::load('linux-container.linux.firefox.headed.automation'))['merged'];

        $this->assertArrayHasKey('headless_gecko_screen', $headless['codes']);
        $this->assertArrayNotHasKey('headless_gecko_screen', $headed['codes']);

        // Negative control: an honest 1366x768 display with a panel is silent.
        $record = self::load('linux-container.linux.firefox.headless.default');
        $record['claims']['tier1']['tier1']['environment']['screen']['availHeight'] = 741;
        $record['claims']['tier1']['tier1']['environment']['screen']['availTop'] = 27;
        $this->assertArrayNotHasKey('headless_gecko_screen', CaptureAnalysis::analyse($record)['merged']['codes']);
    }

    #[Test]
    public function the_expectations_fail_when_a_honest_capture_is_spoofed_headless(): void
    {
        $record = self::load('linux-container.linux.chromium.headed.honest');
        $record['claims']['tier1']['tier1']['environment']['identity']['userAgent'] = str_replace('Chrome/', 'HeadlessChrome/', $record['claims']['tier1']['tier1']['environment']['identity']['userAgent']);

        $failures = Expectations::evaluate($record, CaptureAnalysis::analyse($record), Expectations::load());

        $this->assertContains('ua_headless_token', array_column($failures, 'code'));
    }

    #[Test]
    public function the_expectations_fail_when_headless_chromium_stops_being_detected(): void
    {
        $record = self::load('linux-container.linux.chromium.headless.default');
        // The token is in the UA, appVersion, the client-hint brands and the request headers:
        // all of them are scrubbed, so only a rule that works from other evidence could still fire.
        /** @var array<string, mixed> $record */
        $record = json_decode(str_replace('HeadlessChrome', 'Chrome', (string) json_encode($record)), true, 64, JSON_THROW_ON_ERROR);

        $failures = Expectations::evaluate($record, CaptureAnalysis::analyse($record), Expectations::load());

        $this->assertContains('rule_silent', array_column($failures, 'kind'));
    }

    #[Test]
    public function the_expectations_fail_when_an_honest_capture_reports_webdriver(): void
    {
        $record = self::load('linux-container.linux.chromium.headed.honest');
        $record['claims']['tier1']['tier1']['environment']['identity']['webdriver'] = true;

        $failures = Expectations::evaluate($record, CaptureAnalysis::analyse($record), Expectations::load());

        $this->assertContains('penalty_present', array_column($failures, 'kind'));
    }

    #[Test]
    public function headed_chromium_and_firefox_on_one_machine_link_without_a_veto(): void
    {
        $chromium = self::load('linux-container.linux.chromium.headed.honest');
        $firefox = self::load('linux-container.linux.firefox.headed.automation');

        foreach ([CaptureAnalysis::match($chromium, $firefox), CaptureAnalysis::match($firefox, $chromium)] as $result) {
            $this->assertNotNull($result);
            $this->assertNull($result['veto'], (string) $result['veto']);
            $this->assertTrue($result['linked']);
            $this->assertTrue($result['hardware_key_equal']);
        }
    }

    #[Test]
    public function a_capture_from_another_machine_class_does_not_link(): void
    {
        $chromium = self::load('linux-container.linux.chromium.headed.honest');
        $other = self::load('linux-container.linux.firefox.headed.automation');
        // Same claims, but a Windows desktop: the hard components (os) no longer agree.
        $other['claims']['tier1']['tier1']['environment']['identity']['userAgent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0';
        $other['claims']['tier1']['tier1']['environment']['identity']['platform'] = 'Win32';

        $result = CaptureAnalysis::match($chromium, $other);

        $this->assertNotNull($result);
        $this->assertFalse($result['linked']);
    }

    #[Test]
    public function the_dataset_features_are_flat_scalars(): void
    {
        $features = CaptureAnalysis::features(CaptureAnalysis::mergedClaims(self::load('linux-container.linux.firefox.headless.default')));

        $this->assertNotEmpty($features);
        $this->assertNotEmpty(array_filter(array_keys($features), static fn (string $key): bool => str_starts_with($key, 'tier1.environment.identity.')));
        foreach ($features as $value) {
            $this->assertTrue($value === null || is_scalar($value));
        }
    }
}

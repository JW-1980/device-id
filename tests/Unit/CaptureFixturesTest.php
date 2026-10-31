<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\Capture\Expectations;
use NutriCompare\Fingerprint\Support\Config;
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
        $this->assertSame('challenge', $answer['band']);
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

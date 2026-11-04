<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../tools/capture/CaptureAnalysis.php';

/**
 * The red-team regression guard: the engine over the runs `npm run redteam` saved
 * (`tests/Fixtures/fingerprint/redteam/`, free stealth and anti-detect tools driving Chromium 153 on a
 * Linux container, real collector, headless and headed).
 *
 * `expectations.json` states, per run, what the engine must say:
 *  - `flagged: true`: band challenge or block, with the listed codes among those that fired.
 *    A rule that stops catching the tool fails the test.
 *  - `flagged: false`: the engine does NOT catch this tool in this mode, and `undetected_reason` says why
 *    (the measured evidence, not a hope). If detection improves this fails on purpose: promote the entry.
 *
 * The fixtures hold what the browser said, never what the engine answered, so a rule change is judged on
 * the same tool output. They are one container's output, not Windows or macOS hardware.
 */
final class RedteamFixturesTest extends TestCase
{
    private const DIRECTORY = __DIR__.'/../Fixtures/fingerprint/redteam';

    /**
     * Tools with no headed mode (Lightpanda has no window), so one headless run is the whole set.
     */
    private const HEADLESS_ONLY = ['lightpanda', 'lightpanda-spoofed'];

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
     * @return array<string, array<string, mixed>>
     */
    private static function expectations(): array
    {
        /** @var array<string, array<string, mixed>> $all */
        $all = json_decode((string) file_get_contents(self::DIRECTORY.'/expectations.json'), true, 16, JSON_THROW_ON_ERROR);

        return $all;
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function spoofRuns(): array
    {
        $out = [];
        foreach (self::expectations() as $id => $expectation) {
            $out[$id] = [$id];
        }

        return $out;
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

    #[Test]
    public function every_fixture_has_an_expectation_and_the_other_way_round(): void
    {
        $files = array_map(static fn (string $f): string => basename($f, '.json'), glob(self::DIRECTORY.'/*.json') ?: []);
        $files = array_values(array_filter($files, static fn (string $f): bool => $f !== 'expectations'));
        sort($files);
        $ids = array_keys(self::expectations());
        sort($ids);

        $this->assertSame($ids, $files);
        $this->assertGreaterThanOrEqual(10, count($ids));
    }

    #[Test]
    #[DataProvider('spoofRuns')]
    public function the_engine_judges_each_tool_run_as_recorded(string $id): void
    {
        $expectation = self::expectations()[$id];
        $record = self::load($id);
        $merged = CaptureAnalysis::analyse($record)['merged'];
        $flagged = in_array($merged['band'], ['challenge', 'block'], true);
        $detail = sprintf('%s: band %s, score %d, codes [%s]', $id, $merged['band'], $merged['score'], implode(', ', array_keys($merged['codes'])));

        $this->assertSame($expectation['tool'], $record['labels']['tool'], $id);
        if ($record['labels']['name'] === 'honest:baseline') {
            // The plainly driven Chromium of the same machine: headed it is an honest-looking browser,
            // headless it announces itself. Its verdict is the reference the tools are compared with.
            $this->assertSame($expectation['flagged'], $flagged, $detail);

            return;
        }

        $this->assertSame('spoof', $record['labels']['class'], $id);
        $this->assertSame('spoof:'.$expectation['tool'], $record['labels']['name'], $id);
        if ($expectation['flagged'] === true) {
            $this->assertTrue($flagged, 'a tool that was caught is no longer flagged. '.$detail);
            foreach ($expectation['codes'] as $code) {
                $this->assertArrayHasKey($code, $merged['codes'], $detail);
            }

            return;
        }

        $this->assertFalse($flagged, 'a tool the engine did not catch is now flagged: promote the expectation. '.$detail);
        $this->assertNotSame('', trim((string) ($expectation['undetected_reason'] ?? '')), 'an undetected run needs its measured reason');
    }

    #[Test]
    public function every_tool_has_a_headless_and_a_headed_run(): void
    {
        $byTool = [];
        foreach (self::expectations() as $expectation) {
            if (($expectation['tool'] ?? '') === 'baseline') {
                continue;
            }
            $byTool[$expectation['tool']][] = $expectation['flagged'] === true;
        }
        $this->assertNotSame([], $byTool);
        foreach ($byTool as $tool => $flags) {
            $this->assertCount(in_array($tool, self::HEADLESS_ONLY, true) ? 1 : 2, $flags, $tool.' needs '.(in_array($tool, self::HEADLESS_ONLY, true) ? 'its headless run' : 'a headless and a headed run'));
        }
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Canonicaliser;
use DeviceId\Keys\DeviceKeyDeriver;
use DeviceId\ProbeRegistry;
use DeviceId\Scoring\ConfidenceScorer;
use DeviceId\Scoring\ProbeOmission;
use DeviceId\Settings;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;
use PHPUnit\Framework\TestCase;

/**
 * The contract between the one browser collector (`resources/js/collector`) and the engine's
 * probe tables: what the collector sends is exactly what `ProbeRegistry` knows and what
 * `ConfidenceScorer` expects, so a host needs no `confidence_probes` override.
 *
 * The collector's source is read as text, the same way IntegrityCodesClassifiedTest reads
 * integrity.ts: a probe added there and forgotten here (or the reverse) fails this test.
 */
final class ProbeSetTest extends TestCase
{
    private const TIER_OF = ['ONE' => 'tier1', 'TWO' => 'tier2', 'HARDWARE' => 'hardware'];

    protected function tearDown(): void
    {
        Config::reset();

        parent::tearDown();
    }

    private static function source(string $file): string
    {
        $source = file_get_contents(__DIR__.'/../../resources/js/collector/'.$file);
        self::assertIsString($source, $file.' must be readable');

        return $source;
    }

    /**
     * The `VALUE_PROBES` entries of value-probes.ts: name => registry tier.
     *
     * @return array<string, string>
     */
    private static function collectorValueProbes(): array
    {
        $source = self::source('value-probes.ts');
        $start = strpos($source, 'export const VALUE_PROBES');
        self::assertNotFalse($start, 'VALUE_PROBES must be declared in value-probes.ts');

        $registry = substr($source, $start, (int) strpos($source, "\n];", $start) - $start);
        preg_match_all("/^\s*\{ name: '(\w+)', tier: TIER\.(ONE|TWO|HARDWARE)/m", $registry, $matches, PREG_SET_ORDER);

        $probes = [];
        foreach ($matches as [, $name, $tier]) {
            $probes[$name] = self::TIER_OF[$tier];
        }

        return $probes;
    }

    public function test_the_collector_declares_a_non_trivial_probe_set(): void
    {
        $this->assertGreaterThan(30, count(self::collectorValueProbes()));
    }

    public function test_every_collector_value_probe_is_in_the_registry_with_the_same_tier_and_nothing_else_is(): void
    {
        $registry = [];
        foreach (ProbeRegistry::methods() as $name => $method) {
            if ($method['tier'] !== ProbeRegistry::TIER_INTEGRITY) {
                $registry[$name] = $method['tier'];
            }
        }

        $collector = self::collectorValueProbes();
        ksort($registry);
        ksort($collector);

        $this->assertSame($collector, $registry);
    }

    public function test_the_registry_probe_set_is_the_collectors(): void
    {
        preg_match('/export const PROBE_SET = (\d+);/', self::source('protocol.ts'), $match);

        $this->assertSame((int) ($match[1] ?? 0), ProbeRegistry::PROBE_SET);
    }

    public function test_the_core_probes_are_the_same_list_on_both_sides(): void
    {
        preg_match('/export const CORE_PROBES: readonly string\[\] = \[(.*?)\n\];/s', self::source('protocol.ts'), $block);
        preg_match_all("/'(\w+)'/", preg_replace('#//[^\n]*#', '', $block[1] ?? '') ?? '', $names);

        $collector = $names[1];
        $registry = ProbeRegistry::core();
        sort($collector);
        sort($registry);

        $this->assertSame($registry, $collector);
    }

    public function test_every_registry_integrity_probe_exists_in_the_collectors_integrity_module(): void
    {
        $integrity = self::source('integrity.ts');

        foreach (ProbeRegistry::methods() as $name => $method) {
            if ($method['tier'] === ProbeRegistry::TIER_INTEGRITY) {
                $this->assertMatchesRegularExpression('/\b'.$name.'\b/', $integrity, "integrity probe {$name} is not in integrity.ts");
            }
        }
    }

    public function test_the_shipped_confidence_catalogue_is_exactly_the_collectors_value_probes(): void
    {
        Config::reset();

        $expected = [];
        foreach (self::collectorValueProbes() as $name => $tier) {
            $expected[] = ($tier === 'tier1' ? 'tier1:' : 'tier2:').$name;
        }
        $actual = array_keys(ConfidenceScorer::catalogue());
        sort($expected);
        sort($actual);

        $this->assertSame($expected, $actual, 'a host must not need a confidence_probes override');
    }

    public function test_probes_added_by_the_merge_belong_to_probe_set_three_and_are_switchable(): void
    {
        foreach (['webrtc', 'behavior'] as $name) {
            $this->assertSame(3, ProbeRegistry::PROBE_SET_ADDED[$name]);
            $this->assertFalse(ProbeRegistry::isCore($name), $name.' must be switchable by the operator');
            $this->assertArrayHasKey($name, ProbeRegistry::methods(3));
            $this->assertArrayNotHasKey($name, ProbeRegistry::methods(2), 'a probe-set-2 bundle never sent '.$name);
        }
    }

    public function test_behavior_is_off_by_default_and_a_default_disabled_probe_is_excused_from_coverage(): void
    {
        $this->assertContains('behavior', ProbeRegistry::disabled(), 'owner decision: the behaviour probe is off until an operator switches it on');
        $this->assertNotContains('behavior', ProbeRegistry::disabled(new Settings(['disabled_probes' => []])), 'an explicit empty list switches it on');

        $scorer = new ConfidenceScorer;
        $withPolicy = $scorer->score([], null, ProbeRegistry::disabled());
        $withoutPolicy = $scorer->score([], null, []);

        foreach (['tier2:behavior', 'tier2:parallelism'] as $key) {
            $this->assertNotContains($key, $withPolicy->missing, $key.' is excused by the default policy');
            $this->assertContains($key, $withoutPolicy->missing, 'negative control: without the policy it is expected');
        }
        $this->assertSame(
            $withoutPolicy->expected - ConfidenceScorer::catalogue()['tier2:behavior']['weight'] - ConfidenceScorer::catalogue()['tier2:parallelism']['weight'],
            $withPolicy->expected,
        );
    }

    public function test_the_integrity_probes_added_in_set_four_are_switchable_and_judged_only_for_bundles_that_have_them(): void
    {
        foreach (['canvasPattern', 'automationMarks'] as $name) {
            $this->assertSame(4, ProbeRegistry::PROBE_SET_ADDED[$name]);
            $this->assertFalse(ProbeRegistry::isCore($name), $name.' must be switchable by the operator');
            $this->assertSame(ProbeRegistry::TIER_INTEGRITY, ProbeRegistry::methods(4)[$name]['tier']);
            $this->assertArrayNotHasKey($name, ProbeRegistry::methods(3), 'a probe-set-3 bundle never sent '.$name);
            $this->assertContains('integrity:'.$name, ProbeOmission::expectedFor(ProbeOmission::SLOT_TIER1, [], 4));
            $this->assertNotContains('integrity:'.$name, ProbeOmission::expectedFor(ProbeOmission::SLOT_TIER1, [], 3), 'an older bundle is not charged for a probe it does not have');
            $this->assertNotContains('integrity:'.$name, ProbeOmission::expectedFor(ProbeOmission::SLOT_TIER1, [$name], 4), 'a switched-off probe is not expected');
        }

        // The deferred phase re-measures the canvas pattern for the tier-2 envelope's trust decision.
        $this->assertContains('integrity:canvasPattern', ProbeOmission::expectedFor(ProbeOmission::SLOT_TIER2, [], 4));
        $this->assertNotContains('integrity:automationMarks', ProbeOmission::expectedFor(ProbeOmission::SLOT_TIER2, [], 4));
    }

    public function test_the_client_findings_of_the_new_probes_are_dropped_with_their_probe(): void
    {
        $claims = [
            'integrity' => [
                'findings' => [['code' => 'canvas_pattern_perturbed'], ['code' => 'automation_global_present'], ['code' => 'headless_shell_geometry'], ['code' => 'lie_battery_failed']],
                'data' => ['canvasPattern' => ['state' => 'ok', 'value' => ['exact' => false, 'deviations' => 2, 'stable' => true]], 'automationMarks' => ['state' => 'ok', 'value' => ['globals' => 1]]],
            ],
        ];

        $stripped = ProbeRegistry::stripDisabled($claims, ['canvasPattern', 'automationMarks']);

        $this->assertSame([['code' => 'lie_battery_failed']], $stripped['integrity']['findings']);
        $this->assertArrayNotHasKey('canvasPattern', $stripped['integrity']['data']);
        $this->assertArrayNotHasKey('automationMarks', $stripped['integrity']['data']);
    }

    /**
     * @return array<string, array<array-key, mixed>>
     */
    private static function fixtureClaims(): array
    {
        $claims = json_decode((string) file_get_contents(__DIR__.'/../Fixtures/fingerprint/claims-chromium.json'), true, 64, JSON_THROW_ON_ERROR);
        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * @param  array<array-key, mixed>  $claims
     * @return array{0: string|null, 1: string|null}
     */
    private static function keysOf(array $claims): array
    {
        Config::use(['fingerprint' => ['device_key_secret' => 'probe-set-test-secret-0123456789abcdef']]);
        $keys = (new DeviceKeyDeriver)->keys($claims, new TransportIntegrityResult);
        self::assertNotNull($keys);

        return [$keys->browserKey, $keys->hardwareKey];
    }

    public function test_neither_webrtc_nor_behavior_reaches_a_device_key(): void
    {
        $claims = self::fixtureClaims();
        $bare = self::keysOf($claims);
        $this->assertNotNull($bare[0], 'the fixture must produce a browser key for this test to mean anything');

        $withNew = $claims;
        $withNew['tier2']['webrtc'] = ['audio' => ['count' => 8, 'hash' => 'aaaaaaaa'], 'video' => ['count' => 34, 'hash' => 'bbbbbbbb'], 'extensions' => ['count' => 15, 'hash' => 'cccccccc'], 'sdpHash' => 'dddddddd'];
        $withNew['tier2']['behavior'] = ['elapsedMs' => 1200.5, 'pointer' => ['moves' => 40], 'keyboard' => ['down' => 3, 'codesHash' => '1234abcd']];
        $this->assertSame($bare, self::keysOf($withNew));

        $other = $withNew;
        $other['tier2']['webrtc']['sdpHash'] = 'eeeeeeee';
        $other['tier2']['behavior'] = ['elapsedMs' => 9.1, 'pointer' => ['moves' => 4000]];
        $this->assertSame($bare, self::keysOf($other), 'a different session must not be a different device');
    }

    public function test_the_key_test_would_notice_a_key_input(): void
    {
        // The proof that the assertion above can fail: a tier-1 identity field IS in the key.
        $claims = self::fixtureClaims();
        $changed = $claims;
        $changed['tier1']['environment']['identity']['hardwareConcurrency'] = 77;

        $this->assertNotSame(self::keysOf($claims)[0], self::keysOf($changed)[0]);
        $this->assertNotSame(Canonicaliser::canonicalise($claims), Canonicaliser::canonicalise($changed));
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Rules\IntegrityFindings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * IntegrityFindings: the server re-derives the client's integrity findings from the client's
 * own integrity data (notes/24 F10).
 *
 * The three properties that matter, each tested against REAL captured data rather than a
 * hand-written approximation of it:
 *
 * 1. silence on honest data — the captured wire output of a stock Chromium, Firefox and WebKit
 *    (tests/Fixtures/fingerprint/honest-integrity.json), in every envelope form the server
 *    receives (tier-1, tier-2, the identify path's merged set), derives nothing;
 * 2. an EMPTY findings array next to tell-tale data still yields the code, for every derivable
 *    code, and only that code;
 * 3. hostile shapes never throw, and never fire a rule the client would not fire on the same
 *    value.
 */
final class IntegrityFindingsTest extends TestCase
{
    private const FIXTURE = __DIR__.'/../Fixtures/fingerprint/honest-integrity.json';

    /**
     * The captured honest envelopes, per engine: `[engine => [form => claims]]`, forms being
     * the tier-1 envelope, the tier-2 envelope and the identify path's merged claim set
     * (index.ts `mergeIntegrity`: findings concatenated, deferred data winning).
     *
     * @return array<string, array<string, array<string, mixed>>>
     */
    private static function honestEnvelopes(): array
    {
        $fixture = json_decode((string) file_get_contents(self::FIXTURE), true, 64, JSON_THROW_ON_ERROR);
        self::assertIsArray($fixture);
        self::assertIsArray($fixture['engines'] ?? null);

        $out = [];
        foreach ($fixture['engines'] as $engine => $capture) {
            self::assertIsArray($capture);
            $sync = $capture['sync'];
            $deferred = $capture['deferred'];
            self::assertIsArray($sync);
            self::assertIsArray($deferred);
            self::assertIsArray($sync['data']);
            self::assertIsArray($deferred['data']);
            self::assertIsArray($sync['findings']);
            self::assertIsArray($deferred['findings']);

            $out[(string) $engine] = [
                'tier1' => ['integrity' => $sync],
                'tier2' => ['integrity' => $deferred],
                'identify' => ['integrity' => [
                    'findings' => [...$sync['findings'], ...$deferred['findings']],
                    'data' => array_replace($sync['data'], $deferred['data']),
                ]],
            ];
        }

        return $out;
    }

    /**
     * The honest Chromium claim set in the identify form: every integrity probe present.
     *
     * @return array<string, mixed>
     */
    private static function honest(): array
    {
        return self::honestEnvelopes()['chromium']['identify'];
    }

    /**
     * `$claims` with values set inside one integrity probe's value (its `{state, value}`
     * envelope is kept). A patch is a list of `[segments, value]`: segments rather than a
     * dotted path, because `wrongReceiver`'s own keys contain dots (`navigator.userAgent`).
     *
     * @param  array<array-key, mixed>  $claims
     * @param  list<array{0: list<string>, 1: mixed}>  $patch
     * @return array<array-key, mixed>
     */
    public static function tamper(array $claims, string $probe, array $patch): array
    {
        $integrity = is_array($claims['integrity'] ?? null) ? $claims['integrity'] : [];
        $data = is_array($integrity['data'] ?? null) ? $integrity['data'] : [];
        $envelope = is_array($data[$probe] ?? null) ? $data[$probe] : ['state' => 'ok', 'value' => []];
        $value = is_array($envelope['value'] ?? null) ? $envelope['value'] : [];

        foreach ($patch as [$segments, $set]) {
            $value = self::setPath($value, $segments, $set);
        }

        $envelope['state'] = 'ok';
        $envelope['value'] = $value;
        $data[$probe] = $envelope;
        $integrity['data'] = $data;
        $claims['integrity'] = $integrity;

        return $claims;
    }

    /**
     * @param  array<array-key, mixed>  $node
     * @param  list<string>  $segments
     * @return array<array-key, mixed>
     */
    private static function setPath(array $node, array $segments, mixed $value): array
    {
        $head = array_shift($segments);
        if ($head === null) {
            return $node;
        }

        $node[$head] = $segments === []
            ? $value
            : self::setPath(is_array($node[$head] ?? null) ? $node[$head] : [], $segments, $value);

        return $node;
    }

    /**
     * The value at `$path` inside a decoded claim tree, or null when any step is missing or
     * not an array. Test-side reading only; the production reader is under test.
     */
    private static function dig(mixed $node, string ...$path): mixed
    {
        foreach ($path as $key) {
            if (! is_array($node) || ! array_key_exists($key, $node)) {
                return null;
            }
            $node = $node[$key];
        }

        return $node;
    }

    /**
     * One tell-tale per derivation rule: the probe, the patch (see `tamper`), and the ONE
     * code it must produce. Shared with EnvironmentConsistencyTest, which checks the same
     * patches reach the contradiction list.
     *
     * @return iterable<string, array{0: string, 1: list<array{0: list<string>, 1: mixed}>, 2: string}>
     */
    public static function tellTaleProvider(): iterable
    {
        yield 'wrongReceiver did-not-throw' => ['wrongReceiver', [[['navigator.userAgent'], 'did-not-throw']], 'wrong_receiver_did_not_throw'];

        yield 'descriptor not native (P)' => ['descriptorIntegrity', [[['userAgent'], 'PS-ce-']], 'descriptor_patched'];
        yield 'descriptor unstable getter (U)' => ['descriptorIntegrity', [[['platform'], 'NU-ce-']], 'descriptor_unstable'];
        yield 'descriptor setter (W)' => ['descriptorIntegrity', [[['hardwareConcurrency'], 'NSWce-']], 'descriptor_has_setter'];
        yield 'descriptor shadowed (o)' => ['descriptorIntegrity', [[['userAgent'], 'NS-ceo']], 'descriptor_shadowed'];
        // `navigator.webdriver` reachable (webdriverPresence.present stays true) but no
        // descriptor: an instance-level replacement of a deleted attribute.
        yield 'webdriver reachable without a descriptor' => ['descriptorIntegrity', [[['webdriver'], 'no-descriptor']], 'descriptor_missing'];

        yield 'math agreement flag false' => ['mathDual', [[['tanhAgrees'], false]], 'math_pf_mismatch'];
        yield 'math agreement flag absent' => ['mathDual', [[['asinhAgrees'], null]], 'math_pf_mismatch'];
        // The flags all say true, the operands they were computed from disagree: a body
        // whose verdicts were edited and whose evidence was not.
        yield 'math operands disagree under a true flag' => ['mathDual', [[['tanh'], 0.76]], 'math_pf_mismatch'];
        // JSON has no NaN/Infinity: a non-finite `*Pf` arrives as null.
        yield 'math Pf non-finite (null on the wire)' => ['mathDual', [[['acoshPf'], null]], 'math_pf_mismatch'];

        yield 'canvas dual agree false' => ['canvasDual', [[['agree'], false]], 'canvas_dual_diverged'];
        yield 'canvas dual hashes differ under agree true' => ['canvasDual', [[['putHash'], '00000000:0']], 'canvas_dual_diverged'];
        yield 'canvas winding differ false' => ['canvasDual', [[['winding', 'differ'], false]], 'canvas_winding_false'];
        yield 'canvas winding samples equal under differ true' => ['canvasDual', [[['winding', 'evenodd'], 255]], 'canvas_winding_false'];

        yield 'dom blocker read threw' => ['domBlockers', [[['chromeRuntime'], 'throw:TypeError']], 'dom_blocker_threw'];
        yield 'selenium global present' => ['domBlockers', [[['windowSeleniumEvaluate'], 'function']], 'dom_blocker_present'];
        yield 'webdriver evaluate global present' => ['domBlockers', [[['windowWebdriverEvaluate'], 'function']], 'dom_blocker_present'];
        yield 'nightmare global present' => ['domBlockers', [[['windowNightmare'], 'function']], 'dom_blocker_present'];

        yield 'webdriver attribute deleted' => ['webdriverPresence', [[['present'], false]], 'webdriver_missing'];

        yield 'canvas fill not exact' => ['canvasFill', [[['exact'], false], [['deviations'], 12]], 'canvas_readback_perturbed'];
        yield 'canvas fill deviations under exact true' => ['canvasFill', [[['deviations'], 3844]], 'canvas_readback_perturbed'];

        yield 'canvas pattern not exact' => ['canvasPattern', [[['exact'], false], [['deviations'], 9]], 'canvas_pattern_perturbed'];
        yield 'canvas pattern deviations under exact true' => ['canvasPattern', [[['deviations'], 4]], 'canvas_pattern_perturbed'];

        yield 'automation global present' => ['automationMarks', [[['globals'], 1]], 'automation_global_present'];
        yield 'headless shell geometry' => ['automationMarks', [[['outerEqualsInner'], true], [['historyLength'], 1]], 'headless_shell_geometry'];

        yield 'lie battery lied' => ['lieBattery', [[['lied'], ['Navigator.userAgent' => 'to_string']]], 'lie_battery_failed'];

        yield 'realm toString mismatch' => ['phantomRealm', [[['nativeToString', 'mismatched'], ['Navigator.userAgent']]], 'realm_tostring_mismatch'];
        yield 'domRect arithmetic' => ['phantomRealm', [[['domRect', 'math'], false]], 'domrect_inconsistent'];
        yield 'domRect twins differ' => ['phantomRealm', [[['domRect', 'identical'], false]], 'domrect_inconsistent'];
        yield 'domRect ghost not zero' => ['phantomRealm', [[['domRect', 'ghost'], false]], 'domrect_inconsistent'];
        yield 'svg repeat unequal' => ['phantomRealm', [[['svgText', 'repeatEqual'], false]], 'svg_text_inconsistent'];
        yield 'svg bbox disagrees' => ['phantomRealm', [[['svgText', 'bboxAgrees'], false]], 'svg_text_inconsistent'];
    }

    // ---------------------------------------------------------------------
    // 1. Honest data derives nothing
    // ---------------------------------------------------------------------

    #[Test]
    public function captured_honest_data_from_three_engines_derives_nothing_in_any_envelope_form(): void
    {
        $envelopes = self::honestEnvelopes();
        self::assertSame(['chromium', 'firefox', 'webkit'], array_keys($envelopes));

        foreach ($envelopes as $engine => $forms) {
            foreach ($forms as $form => $claims) {
                // Precondition: the capture really carries the data, so silence is earned.
                $data = self::dig($claims, 'integrity', 'data');
                self::assertIsArray($data);
                self::assertNotSame([], $data, "{$engine} {$form}: no integrity data captured");

                self::assertSame([], IntegrityFindings::derived($claims), "{$engine} {$form}: honest data derived a finding");
                self::assertSame([], IntegrityFindings::effective($claims), "{$engine} {$form}: honest envelope has effective findings");
            }

            // The identify form carries every probe either phase sends.
            $identify = self::dig($forms['identify'], 'integrity', 'data');
            self::assertIsArray($identify);
            foreach (['wrongReceiver', 'descriptorIntegrity', 'mathDual', 'canvasDual', 'domBlockers', 'webdriverPresence', 'canvasFill', 'lieBattery', 'phantomRealm'] as $probe) {
                self::assertArrayHasKey($probe, $identify, "{$engine}: the capture lacks {$probe}");
            }
        }
    }

    #[Test]
    public function honest_engine_variation_is_not_evidence(): void
    {
        // The honest differences the capture contains, asserted so the silence above is
        // known to cover them: Firefox and WebKit lack descriptors for APIs they never
        // implemented, and two of the four math agreements are one ulp apart in Chromium.
        $envelopes = self::honestEnvelopes();

        $webkitShapes = self::dig($envelopes['webkit']['tier1'], 'integrity', 'data', 'descriptorIntegrity', 'value');
        self::assertIsArray($webkitShapes);
        self::assertSame('no-descriptor', $webkitShapes['credentials'] ?? null);
        self::assertSame('no-descriptor', $webkitShapes['userAgentData'] ?? null);

        $math = self::dig($envelopes['chromium']['tier1'], 'integrity', 'data', 'mathDual', 'value');
        self::assertIsArray($math);
        self::assertNotSame($math['asinh'], $math['asinhPf'], 'precondition: an honest one-ulp difference');
        self::assertSame([], IntegrityFindings::derived($envelopes['chromium']['tier1']));
    }

    // ---------------------------------------------------------------------
    // 2. Omitting the finding no longer hides it
    // ---------------------------------------------------------------------

    /**
     * @param  list<array{0: list<string>, 1: mixed}>  $patch
     */
    #[Test]
    #[DataProvider('tellTaleProvider')]
    public function tell_tale_data_with_an_empty_findings_array_still_yields_the_code(string $probe, array $patch, string $expected): void
    {
        $claims = self::tamper(self::honest(), $probe, $patch);
        self::assertSame([], self::dig($claims, 'integrity', 'findings'), 'precondition: the client reported nothing');

        // Exactly the one code: a tell-tale must not trip a neighbouring rule.
        self::assertSame([$expected], IntegrityFindings::derived($claims));
        self::assertSame([$expected => IntegrityFindings::PROVENANCE_SERVER], IntegrityFindings::effective($claims));
    }

    #[Test]
    public function every_derived_code_has_a_tell_tale_case(): void
    {
        $covered = array_unique(array_map(static fn (array $case): string => $case[2], iterator_to_array(self::tellTaleProvider())));
        sort($covered);
        $derived = IntegrityFindings::DERIVED_CODES;
        sort($derived);

        self::assertSame($derived, $covered);
    }

    #[Test]
    public function the_webdriver_deletion_is_webdriver_missing_and_not_descriptor_missing(): void
    {
        // The client's rule: a deleted attribute is unreachable, so `no-descriptor` alone is
        // not `descriptor_missing`; `webdriverPresence` raises `webdriver_missing` instead.
        $claims = self::tamper(self::tamper(self::honest(), 'descriptorIntegrity', [[['webdriver'], 'no-descriptor']]), 'webdriverPresence', [[['present'], false]]);

        self::assertSame(['webdriver_missing'], IntegrityFindings::derived($claims));
    }

    #[Test]
    public function a_missing_descriptor_on_any_other_name_is_not_derivable(): void
    {
        // Firefox and WebKit honestly lack these: the client needs `name in navigator` to
        // tell, and that is not sent. Deriving it would flag every honest Safari.
        $claims = self::tamper(self::honest(), 'descriptorIntegrity', [[['credentials'], 'no-descriptor'], [['userAgentData'], 'no-descriptor']]);

        self::assertSame([], IntegrityFindings::derived($claims));
    }

    #[Test]
    public function the_deferred_canvas_fill_in_a_tier_two_envelope_is_derived_too(): void
    {
        $tier2 = self::honestEnvelopes()['firefox']['tier2'];
        $claims = self::tamper($tier2, 'canvasFill', [[['exact'], false], [['deviations'], 7]]);

        self::assertSame(['canvas_readback_perturbed'], IntegrityFindings::derived($claims));
    }

    // ---------------------------------------------------------------------
    // Provenance, and the client's own assertions
    // ---------------------------------------------------------------------

    #[Test]
    public function provenance_names_who_saw_each_code(): void
    {
        $claims = self::tamper(self::honest(), 'descriptorIntegrity', [[['userAgent'], 'PS-ce-'], [['platform'], 'NSWce-']]);
        $claims = self::withFindings($claims, [
            ['code' => 'descriptor_patched'],          // reported, and the data shows it
            ['code' => 'descriptor_missing'],          // reported, and not derivable here
            ['code' => 'descriptor_patched', 'detail' => 'duplicate entry'],
        ]);

        self::assertSame([
            'descriptor_patched' => IntegrityFindings::PROVENANCE_BOTH,
            'descriptor_missing' => IntegrityFindings::PROVENANCE_CLIENT,
            'descriptor_has_setter' => IntegrityFindings::PROVENANCE_SERVER,
        ], IntegrityFindings::effective($claims));
    }

    #[Test]
    public function a_client_finding_its_own_data_contradicts_is_kept(): void
    {
        // The data is clean, the client says otherwise. Kept: a finding only ever counts
        // against the client that sends it (class docblock).
        foreach (IntegrityFindings::DERIVED_CODES as $code) {
            $claims = self::honest();
            $claims = self::withFindings($claims, [['code' => $code]]);

            self::assertSame([$code => IntegrityFindings::PROVENANCE_CLIENT], IntegrityFindings::effective($claims), $code);
        }
    }

    #[Test]
    public function an_unknown_but_well_formed_client_code_is_kept_and_a_malformed_one_is_not(): void
    {
        $claims = self::honest();
        $claims = self::withFindings($claims, [
            ['code' => 'some_future_check'],
            ['code' => 'UPPER_CASE'],
            ['code' => str_repeat('a', 65)],
            ['code' => 'has space'],
            ['code' => 5],
            ['code' => ['descriptor_patched']],
            ['detail' => 'no code'],
            'descriptor_patched',
            null,
        ]);

        self::assertSame(['some_future_check' => IntegrityFindings::PROVENANCE_CLIENT], IntegrityFindings::effective($claims));
    }

    // ---------------------------------------------------------------------
    // 3. Hostile shapes
    // ---------------------------------------------------------------------

    /**
     * Shapes the client never sends. Each must not throw, and must derive exactly what the
     * client's own rule would derive from the same value (JavaScript semantics).
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: list<string>}>
     */
    public static function hostileProvider(): iterable
    {
        yield 'no claims' => [[], []];
        yield 'integrity is a string' => [['integrity' => 'x'], []];
        yield 'data and findings are scalars' => [['integrity' => ['data' => 5, 'findings' => 'descriptor_patched']], []];
        yield 'data is a list' => [['integrity' => ['data' => [1, 2, 3]]], []];

        // Tagged states are "not measured", exactly as `state === 'ok'` / `subValue()` read them.
        yield 'randomised canvas dual' => [self::data(['canvasDual' => ['state' => 'unavailable', 'reason' => 'randomised']]), []];
        yield 'errored probes' => [self::data([
            'wrongReceiver' => ['state' => 'error', 'name' => 'TypeError'],
            'mathDual' => ['state' => 'error', 'name' => 'TypeError'],
            'canvasFill' => ['state' => 'unavailable', 'reason' => 'no-2d-context'],
            'webdriverPresence' => ['state' => 'error', 'name' => 'SecurityError'],
        ]), []];
        yield 'an unrecognised state' => [self::data(['canvasFill' => ['state' => 'weird', 'value' => ['exact' => false]]]), []];
        yield 'no realm' => [self::data(['phantomRealm' => ['state' => 'unavailable', 'reason' => 'no-realm']]), []];
        yield 'tagged realm sub-results' => [self::data(['phantomRealm' => ['state' => 'ok', 'value' => [
            'nativeToString' => ['state' => 'unavailable', 'reason' => 'realm-tampered', 'mismatched' => ['Navigator.userAgent']],
            'domRect' => ['state' => 'error', 'name' => 'TypeError'],
            'svgText' => ['state' => 'unavailable', 'reason' => 'no-svg-text'],
        ]]]), []];
        yield 'winding unavailable or errored (honest forms)' => [self::data(['canvasDual' => ['state' => 'ok', 'value' => ['agree' => true, 'fillHash' => 'a', 'putHash' => 'a', 'winding' => 'error:TypeError']]]), []];

        // Wrong types where the client's rule would not fire either.
        yield 'scalar probe values' => [self::data([
            'wrongReceiver' => ['state' => 'ok', 'value' => 'did-not-throw'],
            'descriptorIntegrity' => ['state' => 'ok', 'value' => 'PUW-eo'],
            'mathDual' => ['state' => 'ok', 'value' => 42],
            'domBlockers' => ['state' => 'ok', 'value' => 'throw:TypeError'],
            'lieBattery' => ['state' => 'ok', 'value' => true],
        ]), []];
        yield 'non-string shapes and verdicts' => [self::data([
            'wrongReceiver' => ['state' => 'ok', 'value' => ['a' => ['did-not-throw'], 'b' => true]],
            'descriptorIntegrity' => ['state' => 'ok', 'value' => ['userAgent' => ['P'], 'webdriver' => 5]],
            'domBlockers' => ['state' => 'ok', 'value' => ['x' => ['throw:'], 'windowNightmare' => ['function']]],
        ]), []];
        yield 'lied with no entries' => [self::data(['lieBattery' => ['state' => 'ok', 'value' => ['lied' => 5]]]), []];
        yield 'present as the string 0 is truthy in JS' => [self::data(['webdriverPresence' => ['state' => 'ok', 'value' => ['present' => '0']]]), []];
        yield 'exact as an empty object is truthy in JS' => [self::data(['canvasFill' => ['state' => 'ok', 'value' => ['exact' => []]]]), []];

        // Wrong types where the client's rule WOULD fire: mirrored, not softened.
        yield 'an empty mathDual has no agreement flags' => [self::data(['mathDual' => ['state' => 'ok', 'value' => []]]), ['math_pf_mismatch']];
        yield 'present as 0' => [self::data(['webdriverPresence' => ['state' => 'ok', 'value' => ['present' => 0]]]), ['webdriver_missing']];
        yield 'exact as an empty string' => [self::data(['canvasFill' => ['state' => 'ok', 'value' => ['exact' => '']]]), ['canvas_readback_perturbed']];
        yield 'lied as a non-empty string' => [self::data(['lieBattery' => ['state' => 'ok', 'value' => ['lied' => 'x']]]), ['lie_battery_failed']];
        yield 'canvas dual without agree' => [self::data(['canvasDual' => ['state' => 'ok', 'value' => ['winding' => 'unavailable']]]), ['canvas_dual_diverged']];
        // A raw (unwrapped) value is read like the rest of the engine reads one.
        yield 'raw unwrapped value' => [self::data(['canvasFill' => ['exact' => false, 'deviations' => 3]]), ['canvas_readback_perturbed']];
    }

    /**
     * @param  array<array-key, mixed>  $claims
     * @param  list<string>  $expected
     */
    #[Test]
    #[DataProvider('hostileProvider')]
    public function a_hostile_shape_never_throws_and_mirrors_the_client(array $claims, array $expected): void
    {
        self::assertSame($expected, IntegrityFindings::derived($claims));
        self::assertSame(array_fill_keys($expected, IntegrityFindings::PROVENANCE_SERVER), IntegrityFindings::effective($claims));
    }

    #[Test]
    public function huge_collections_are_survivable(): void
    {
        $many = 200_000;
        $claims = self::data([
            'descriptorIntegrity' => ['state' => 'ok', 'value' => array_fill(0, $many, 'NS-ce-')],
            'wrongReceiver' => ['state' => 'ok', 'value' => array_fill(0, $many, 'threw:TypeError')],
            'domBlockers' => ['state' => 'ok', 'value' => array_fill(0, $many, false)],
            'mathDual' => ['state' => 'ok', 'value' => [...array_fill(0, $many, 1.0), 'atanhAgrees' => true, 'tanhAgrees' => true, 'expm1Agrees' => true, 'asinhAgrees' => true]],
            'lieBattery' => ['state' => 'ok', 'value' => ['lied' => []]],
        ]);
        $claims = self::withFindings($claims, array_fill(0, $many, ['code' => 'dom_blocker_threw']));

        self::assertSame([], IntegrityFindings::derived($claims));
        self::assertSame(['dom_blocker_threw' => IntegrityFindings::PROVENANCE_CLIENT], IntegrityFindings::effective($claims));
    }

    /**
     * The bound itself, not only survival (sceptical review round 4, SK-6d: removing the cap
     * passed every test). Entry `MAX_ENTRIES + 1` of a collection is never walked, so a
     * footprint placed there derives nothing, and the same footprint inside the bound does.
     */
    #[Test]
    public function only_the_first_max_entries_of_a_collection_are_walked(): void
    {
        $benign = [];
        for ($i = 0; $i < IntegrityFindings::MAX_ENTRIES; $i++) {
            $benign['global'.$i] = false;
        }

        $beyond = self::data(['domBlockers' => ['state' => 'ok', 'value' => [...$benign, 'windowNightmare' => 'function', 'chromeRuntime' => 'throw:TypeError']]]);
        self::assertSame([], IntegrityFindings::derived($beyond), 'entry 513 and later are outside the bound');

        $within = self::data(['domBlockers' => ['state' => 'ok', 'value' => ['windowNightmare' => 'function', 'chromeRuntime' => 'throw:TypeError', ...$benign]]]);
        self::assertSame(['dom_blocker_threw', 'dom_blocker_present'], IntegrityFindings::derived($within), 'precondition: the same footprints inside the bound are derived');

        $findings = [...array_fill(0, IntegrityFindings::MAX_ENTRIES, ['code' => 'dom_blocker_threw']), ['code' => 'math_pf_mismatch']];
        self::assertArrayNotHasKey('math_pf_mismatch', IntegrityFindings::effective(self::withFindings(self::data([]), $findings)), 'a client code after the bound is not lifted');
    }

    /**
     * `$claims` with `integrity.findings` replaced.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<array-key, mixed>  $findings
     * @return array<array-key, mixed>
     */
    private static function withFindings(array $claims, array $findings): array
    {
        $integrity = is_array($claims['integrity'] ?? null) ? $claims['integrity'] : [];
        $integrity['findings'] = $findings;
        $claims['integrity'] = $integrity;

        return $claims;
    }

    /**
     * A claim set whose `integrity.data` is `$data` and whose findings are empty.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    private static function data(array $data): array
    {
        return ['integrity' => ['findings' => [], 'data' => $data]];
    }
}

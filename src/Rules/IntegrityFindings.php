<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Rules;

/**
 * The integrity finding codes that hold for a claim set: what the client reported, united
 * with what the server derives from the client's own raw integrity data.
 *
 * ## Why this exists (notes/24 F10)
 *
 * The client sends `integrity.findings` (its verdicts) AND `integrity.data` (the evidence the
 * verdicts were computed from). Lifting only the verdicts made them self-asserted: an attacker
 * who sends `findings: []` hides every one of them without reading a line of the collector,
 * because the field name is visible in the network tab. Wherever the data the client sends is
 * enough to decide a finding, the server now decides it itself, so dropping a finding while
 * sending its tell-tale data hides nothing. This does not make the data sincere — an attacker
 * who rewrites the data as well still passes — it removes the zero-effort bypass and forces the
 * attacker to understand, and consistently forge, every probe's semantics.
 *
 * ## The rules mirror the client's, line by line
 *
 * Each derivation below is the decision rule in `resources/js/Support/fingerprint/integrity.ts`
 * (`collectIntegrity`, `collectDeferredIntegrity`, `phantomFindings`) applied to the value that
 * rule reads, with JavaScript truthiness (`jsFalsy`) where the client uses `!x`. On the wire
 * (JSON) a non-finite number arrives as `null`, which is why a `null` `*Pf` value counts as
 * non-finite. Three checks go one step further than the client's verdict and recompute it from
 * the raw values the client computed it FROM, because both are sent: `mathDual`'s four
 * agreements (`|f − fPf| < 1e-15`, the client's own epsilon on the client's own two operands)
 * and `canvasDual`'s `agree` (`fillHash === putHash`) and winding (`nonzero !== evenodd`), and
 * `canvasFill`'s `exact` (`deviations === 0`). On honest data the verdict and the recomputation
 * are the same expression over the same numbers, so they cannot disagree.
 *
 * `research/fingerprinting/HOW-IT-WORKS.md` §3.3 lists every code the client can emit and
 * whether it is derivable; `descriptor_missing` is derivable only for `webdriver` (the client's
 * rule needs `name in navigator`, which is sent only for that name, as `webdriverPresence`).
 *
 * ## A client-asserted finding that its own data contradicts is KEPT
 *
 * A finding is evidence against the client that reports it: it adds risk weight and lowers
 * confidence for that observation only, and it cannot be attributed to anybody else. Asserting
 * a false one therefore only hurts the asserter. Dropping it would also be wrong on honest
 * traffic in three measured or designed cases: `descriptor_missing` is mostly not derivable at
 * all; the identify path merges both integrity phases, so `canvasFill` in the data is the
 * DEFERRED re-measure while `canvas_readback_perturbed` came from the synchronous one; and a
 * newer client may report a code this server does not derive. The one place a self-asserted
 * finding could help an attacker is the host's `DeviceComponents::untrusted()` (a noised component is not
 * matched); that buys nothing the attacker could not get by sending different component values,
 * which is why it is not treated as a reason to drop findings here.
 *
 * ## Envelopes and hostile input
 *
 * Probe values are read through `EnvironmentConsistency::read()` (one reader for the whole
 * engine: an `ok` envelope is unwrapped, a raw value is accepted), and anything still carrying
 * a `state` key afterwards — `{state: 'unavailable', reason: 'randomised'}`, a tagged phantom
 * sub-result — is "not measured" and derives nothing, as `result.state === 'ok'` and
 * `subValue()` make it on the client. Wrong types never throw and never fire a rule the client
 * would not have fired on the same value. Every collection is walked at most `MAX_ENTRIES`
 * entries: more than ten times the largest honest list (30 descriptor names), so the work is
 * bounded whatever a host's body limit is, and the cap hides nothing an attacker could not hide
 * by editing the data instead.
 *
 * A pure function of its argument (no container, clock or I/O). Lives only in this package
 * since the one-engine migration (2026-10-21); the application uses this class.
 */
final class IntegrityFindings
{
    /** The client reported the code and its data does not show it (or cannot). */
    public const PROVENANCE_CLIENT = 'client';

    /** The client's data shows the code and the client did not report it. */
    public const PROVENANCE_SERVER = 'server';

    /** Reported by the client and shown by its data. */
    public const PROVENANCE_BOTH = 'both';

    /**
     * The codes the server derives from `integrity.data`. `descriptor_missing` is derived for
     * `navigator.webdriver` only (see the class docblock).
     *
     * @var list<string>
     */
    public const DERIVED_CODES = [
        'wrong_receiver_did_not_throw',
        'descriptor_patched',
        'descriptor_unstable',
        'descriptor_has_setter',
        'descriptor_shadowed',
        'descriptor_missing',
        'math_pf_mismatch',
        'canvas_dual_diverged',
        'canvas_winding_false',
        'dom_blocker_threw',
        'dom_blocker_present',
        'webdriver_missing',
        'canvas_readback_perturbed',
        'lie_battery_failed',
        'realm_tostring_mismatch',
        'domrect_inconsistent',
        'svg_text_inconsistent',
    ];

    /** Entries walked per collection; see the class docblock. */
    public const MAX_ENTRIES = 512;

    /**
     * A client finding code is a stable snake_case identifier (integrity.ts `INTEGRITY_CODES`:
     * "the server stores and indexes them"); anything else names no rule and is ignored.
     */
    private const CODE_PATTERN = '/^[a-z][a-z0-9_]{0,63}$/';

    /** `mathDual` agreement flag => the two values the client compared to compute it. */
    private const MATH_AGREEMENTS = [
        'atanhAgrees' => ['atanh', 'atanhPf'],
        'tanhAgrees' => ['tanh', 'tanhPf'],
        'expm1Agrees' => ['expm1', 'expm1Pf'],
        'asinhAgrees' => ['asinh', 'asinhPf'],
    ];

    /** integrity.ts `mathDual`: `EPSILON`. */
    private const MATH_EPSILON = 1e-15;

    /** integrity.ts `domBlockers` globals that only an automation driver injects. */
    private const AUTOMATION_GLOBALS = ['windowWebdriverEvaluate', 'windowSeleniumEvaluate', 'windowNightmare'];

    /**
     * Every effective integrity code, de-duplicated, with where it came from: client codes in
     * the order reported, then the server-only ones in `DERIVED_CODES` order.
     *
     * @param  array<array-key, mixed>  $claims  a decoded claim set
     * @return array<string, self::PROVENANCE_*>
     */
    public static function effective(array $claims): array
    {
        $derived = array_fill_keys(self::derived($claims), true);
        $effective = [];

        foreach (self::reported($claims) as $code) {
            $effective[$code] = isset($derived[$code]) ? self::PROVENANCE_BOTH : self::PROVENANCE_CLIENT;
        }

        foreach (array_keys($derived) as $code) {
            $effective[$code] ??= self::PROVENANCE_SERVER;
        }

        return $effective;
    }

    /**
     * The client's own finding codes, de-duplicated, in the order reported. Only the `code`
     * is read: the `detail` is attacker-controlled prose and is never used.
     *
     * @param  array<array-key, mixed>  $claims
     * @return list<string>
     */
    public static function reported(array $claims): array
    {
        $integrity = $claims['integrity'] ?? null;
        $findings = is_array($integrity) ? ($integrity['findings'] ?? null) : null;
        if (! is_array($findings)) {
            return [];
        }

        $codes = [];
        foreach (self::bounded($findings) as $finding) {
            $code = is_array($finding) ? ($finding['code'] ?? null) : null;
            if (is_string($code) && preg_match(self::CODE_PATTERN, $code) === 1) {
                $codes[$code] = true;
            }
        }

        return array_keys($codes);
    }

    /**
     * The codes the client's own integrity data shows, in `DERIVED_CODES` order.
     *
     * @param  array<array-key, mixed>  $claims
     * @return list<string>
     */
    public static function derived(array $claims): array
    {
        $found = [];

        self::wrongReceiver($claims, $found);
        self::descriptors($claims, $found);
        self::math($claims, $found);
        self::canvasDual($claims, $found);
        self::domBlockers($claims, $found);
        self::webdriver($claims, $found);
        self::canvasFill($claims, $found);
        self::lieBattery($claims, $found);
        self::phantomRealm($claims, $found);

        return array_values(array_filter(self::DERIVED_CODES, static fn (string $code): bool => isset($found[$code])));
    }

    // -----------------------------------------------------------------------
    // The client's rules (integrity.ts), one method per probe
    // -----------------------------------------------------------------------

    /**
     * `collectIntegrity`: a target whose verdict is exactly `'did-not-throw'`.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function wrongReceiver(array $claims, array &$found): void
    {
        $verdicts = self::probe($claims, 'wrongReceiver');
        if (! is_array($verdicts)) {
            return;
        }

        foreach (self::bounded($verdicts) as $verdict) {
            if ($verdict === 'did-not-throw') {
                $found['wrong_receiver_did_not_throw'] = true;

                return;
            }
        }
    }

    /**
     * `collectIntegrity`'s descriptor block over the shape strings (native N/P, stable S/U,
     * setter W/-, configurable c/C, enumerable e/-, shadowed o/-). `no-descriptor` is a finding
     * only when the name is reachable on `navigator`, which the data tells for `webdriver`
     * alone (`webdriverPresence.present` is `'webdriver' in navigator`).
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function descriptors(array $claims, array &$found): void
    {
        $shapes = self::probe($claims, 'descriptorIntegrity');
        if (! is_array($shapes)) {
            return;
        }

        foreach (self::bounded($shapes) as $name => $shape) {
            if (! is_string($shape)) {
                continue;
            }

            if ($shape === 'no-descriptor') {
                if ($name === 'webdriver' && self::webdriverReachable($claims)) {
                    $found['descriptor_missing'] = true;
                }

                continue;
            }

            if (str_starts_with($shape, 'P')) {
                $found['descriptor_patched'] = true;
            }
            if (str_contains($shape, 'U')) {
                $found['descriptor_unstable'] = true;
            }
            if (str_contains($shape, 'W')) {
                $found['descriptor_has_setter'] = true;
            }
            if (str_ends_with($shape, 'o')) {
                $found['descriptor_shadowed'] = true;
            }
        }
    }

    /**
     * `collectIntegrity`'s mathDual block: an agreement flag that is not exactly `true`, a
     * `*Pf` value that is not finite (`null` on the wire), or — recomputed from the operands
     * the flag was computed from — two values `MATH_EPSILON` or more apart.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function math(array $claims, array &$found): void
    {
        $math = self::probe($claims, 'mathDual');
        if (! is_array($math)) {
            return;
        }

        foreach (self::MATH_AGREEMENTS as $flag => [$value, $independent]) {
            if (($math[$flag] ?? null) !== true) {
                $found['math_pf_mismatch'] = true;

                return;
            }

            $a = $math[$value] ?? null;
            $b = $math[$independent] ?? null;
            if (self::isNumber($a) && self::isNumber($b) && ! (abs((float) $a - (float) $b) < self::MATH_EPSILON)) {
                $found['math_pf_mismatch'] = true;

                return;
            }
        }

        foreach (self::bounded($math) as $key => $value) {
            if (is_string($key) && str_ends_with($key, 'Pf') && ($value === null || (is_float($value) && ! is_finite($value)))) {
                $found['math_pf_mismatch'] = true;

                return;
            }
        }
    }

    /**
     * `collectIntegrity`'s canvasDual block: `!agree`, or the two hashes `agree` was computed
     * from differing; a winding object carrying `differ` that is not exactly `true`, or whose
     * two samples are equal. `unavailable('randomised')` is a tagged state and derives nothing.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function canvasDual(array $claims, array &$found): void
    {
        $canvas = self::probe($claims, 'canvasDual');
        if (! is_array($canvas)) {
            return;
        }

        $fill = $canvas['fillHash'] ?? null;
        $put = $canvas['putHash'] ?? null;
        if (self::jsFalsy($canvas['agree'] ?? null) || (is_string($fill) && is_string($put) && $fill !== $put)) {
            $found['canvas_dual_diverged'] = true;
        }

        $winding = $canvas['winding'] ?? null;
        if (! is_array($winding)) {
            return;
        }

        if (array_key_exists('differ', $winding) && $winding['differ'] !== true) {
            $found['canvas_winding_false'] = true;
        }

        $nonzero = $winding['nonzero'] ?? null;
        $evenodd = $winding['evenodd'] ?? null;
        if (self::isNumber($nonzero) && self::isNumber($evenodd) && (float) $nonzero === (float) $evenodd) {
            $found['canvas_winding_false'] = true;
        }
    }

    /**
     * `collectIntegrity`'s domBlockers block: any value reading `throw:…`, and the three
     * automation globals reading `'function'`.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function domBlockers(array $claims, array &$found): void
    {
        $blockers = self::probe($claims, 'domBlockers');
        if (! is_array($blockers)) {
            return;
        }

        foreach (self::bounded($blockers) as $name => $value) {
            if (is_string($value) && str_starts_with($value, 'throw:')) {
                $found['dom_blocker_threw'] = true;
            }
            if (in_array($name, self::AUTOMATION_GLOBALS, true) && $value === 'function') {
                $found['dom_blocker_present'] = true;
            }
        }
    }

    /**
     * `collectIntegrity`: `!webdriverPresence.present`.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function webdriver(array $claims, array &$found): void
    {
        $presence = self::probe($claims, 'webdriverPresence');
        if (is_array($presence) && self::jsFalsy($presence['present'] ?? null)) {
            $found['webdriver_missing'] = true;
        }
    }

    /**
     * `collectIntegrity`: `!canvasFill.exact`, or `deviations` (which `exact` is computed
     * from) not zero. The deferred phase's re-measure is the same fact about the same canvas,
     * so deriving it there scores nothing twice: disagreements merge one entry per code.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function canvasFill(array $claims, array &$found): void
    {
        $fill = self::probe($claims, 'canvasFill');
        if (! is_array($fill)) {
            return;
        }

        $deviations = $fill['deviations'] ?? null;
        if (self::jsFalsy($fill['exact'] ?? null) || (self::isNumber($deviations) && (float) $deviations !== 0.0)) {
            $found['canvas_readback_perturbed'] = true;
        }
    }

    /**
     * `collectIntegrity`: `Object.entries(lieBattery.lied).length > 0`.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function lieBattery(array $claims, array &$found): void
    {
        $battery = self::probe($claims, 'lieBattery');
        if (is_array($battery) && self::jsNonEmpty($battery['lied'] ?? null)) {
            $found['lie_battery_failed'] = true;
        }
    }

    /**
     * `phantomFindings`: a non-empty `nativeToString.mismatched`; a falsy `domRect.math`,
     * `.identical` or `.ghost`; a falsy `svgText.repeatEqual` or `.bboxAgrees`. A tagged
     * sub-result (`realm-tampered`, `no-svg-text`, an error) derives nothing.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, true>  $found
     */
    private static function phantomRealm(array $claims, array &$found): void
    {
        $toString = self::probe($claims, 'phantomRealm', 'nativeToString');
        if (is_array($toString) && self::jsNonEmpty($toString['mismatched'] ?? null)) {
            $found['realm_tostring_mismatch'] = true;
        }

        $rect = self::probe($claims, 'phantomRealm', 'domRect');
        if (is_array($rect) && (self::jsFalsy($rect['math'] ?? null) || self::jsFalsy($rect['identical'] ?? null) || self::jsFalsy($rect['ghost'] ?? null))) {
            $found['domrect_inconsistent'] = true;
        }

        $svg = self::probe($claims, 'phantomRealm', 'svgText');
        if (is_array($svg) && (self::jsFalsy($svg['repeatEqual'] ?? null) || self::jsFalsy($svg['bboxAgrees'] ?? null))) {
            $found['svg_text_inconsistent'] = true;
        }
    }

    // -----------------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------------

    /**
     * An integrity probe's value (or a sub-result inside it), or null when absent or
     * tagged. See the class docblock on envelopes.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private static function probe(array $claims, string ...$path): mixed
    {
        $value = EnvironmentConsistency::read($claims, 'integrity', 'data', ...$path);

        return is_array($value) && array_key_exists('state', $value) ? null : $value;
    }

    /**
     * `'webdriver' in navigator`, as `webdriverPresence` measured it (JS truthiness).
     *
     * @param  array<array-key, mixed>  $claims
     */
    private static function webdriverReachable(array $claims): bool
    {
        $presence = self::probe($claims, 'webdriverPresence');

        return is_array($presence) && ! self::jsFalsy($presence['present'] ?? null);
    }

    /**
     * The first `MAX_ENTRIES` entries of a collection, keys preserved.
     *
     * @param  array<array-key, mixed>  $items
     * @return array<array-key, mixed>
     */
    private static function bounded(array $items): array
    {
        return count($items) > self::MAX_ENTRIES ? array_slice($items, 0, self::MAX_ENTRIES, true) : $items;
    }

    /**
     * JavaScript's `!value` for a JSON-decoded value: `undefined` (an absent key, read as
     * null), `null`, `false`, `0`, `-0`, `NaN` and `''` are falsy; every array (a JS object
     * or array, even empty) and every other string — `'0'` included — is truthy.
     */
    private static function jsFalsy(mixed $value): bool
    {
        if ($value === null || $value === false || $value === 0 || $value === '') {
            return true;
        }

        return is_float($value) && ($value === 0.0 || is_nan($value));
    }

    /**
     * `Object.entries(value).length > 0` / `value.length > 0` as the client evaluates them on
     * the shapes it sends: a non-empty object or array, or a non-empty string. Numbers,
     * booleans and null have no entries.
     */
    private static function jsNonEmpty(mixed $value): bool
    {
        return (is_array($value) && $value !== []) || (is_string($value) && $value !== '');
    }

    /**
     * A JSON number (`1` decodes to int, `1.5` to float).
     *
     * @phpstan-assert-if-true int|float $value
     */
    private static function isNumber(mixed $value): bool
    {
        return is_int($value) || is_float($value);
    }
}

<?php

declare(strict_types=1);

/**
 * Audit every value probe for the SINGLE-POINT-BYPASS shape.
 *
 * ## The defect this exists to find, and where it was found once
 *
 * `uaClientHints` originally `await`ed `getHighEntropyValues()` and only THEN returned
 * `brands`. So a single assignment —
 *
 *     navigator.userAgentData = { getHighEntropyValues: () => Promise.resolve({}) }
 *
 * — made the probe return nothing at all, and the three rules that compare the reported
 * brands against the `sec-ch-ua` header (`brands_vs_ch_header`, `ua_vs_ch_brand`,
 * `ua_vs_ch_major`) all went quiet together. Three checks, one property, one line of attack.
 *
 * That was found by reading the code after a bug report, not by a test, and only ONE probe
 * was checked. This script checks all of them.
 *
 * ## The shape being looked for
 *
 * A probe that has an EARLY RETURN on a path an attacker controls, where that path skips
 * work whose absence other rules depend on. Concretely, in `value-probes.ts`:
 *
 *  - `await` inside the probe body, so a stubbed Promise never resolves and the probe's
 *    value is whatever the caller defaults it to;
 *  - an early `return` before the values are read;
 *  - a bare `try { … } catch { }` that swallows and returns nothing;
 *  - a `?.` chain whose failure is silent.
 *
 * A bare `?.` on a property that is simply absent is NOT this defect and is not reported:
 * "the browser does not have this API" is a legitimate answer that several rules act on.
 * The difference is whether the absence is expected, and that is judged by hand from the
 * probe's own docblock.
 *
 * ## What it cannot do
 *
 * It reads source, so it can only find the shapes it was told about. It cannot prove a probe
 * is unbypassable, and a PASS here is not a claim of that. The real proof is a stealth spoofer
 * run against real engines; this package has the real-browser capture harness (`tools/capture`)
 * and the spoof tests in `tests/Unit`, not a spoofer run. This script's job is narrower and stated: make sure the shape that was found once is not
 * still present somewhere unchecked.
 *
 * Run: php tools/probe-bypass-shapes.php   (or: composer probe-bypass-shapes)
 */
$root = dirname(__DIR__).DIRECTORY_SEPARATOR;
$probeFile = $root.'resources/js/collector/value-probes.ts';
$indexFile = $root.'resources/js/collector/index.ts';
$integrityFile = $root.'resources/js/collector/integrity.ts';

foreach ([$probeFile, $indexFile, $integrityFile] as $file) {
    if (! is_file($file)) {
        fwrite(STDERR, "missing: {$file}\n");
        exit(1);
    }
}

/**
 * Pull the probe bodies out of the source.
 *
 * ## The first version of this parser was wrong
 *
 * It looked for four-space-indented `name: { … }` entries, on the assumption that the
 * catalogue was a nested object literal. It is not: `value-probes.ts` declares each probe as
 * a top-level `export function name(): ProbeResult<…> { … }` and then lists them in a flat
 * `VALUE_PROBES` array as `{ name: 'x', tier, run: x }`. The parser matched nothing and found
 * 0 probes — which it reported as "the parser is probably wrong", so the self-check earned
 * its keep immediately.
 *
 * So the shape is matched now, and the count is still asserted afterwards. A parser that
 * silently matches nothing would report "no bypass found", which is the most dangerous
 * possible output for an audit like this one.
 */
$source = (string) file_get_contents($probeFile);
$findings = [];
$probeCount = 0;

// `behavior` is registered in value-probes.ts but declared in behavior.ts (the merged
// collector keeps the passive input listeners in their own module), so both files are parsed.
$behaviorFile = $root.'resources/js/collector/behavior.ts';
if (! is_file($behaviorFile)) {
    fwrite(STDERR, "missing: {$behaviorFile}\n");
    exit(1);
}
$lines = explode("\n", $source."\n".(string) file_get_contents($behaviorFile));
$current = null;
$depth = 0;
$body = [];
$startLine = 0;

foreach ($lines as $index => $line) {
    $number = $index + 1;

    if ($current === null) {
        if (preg_match('/^export (?:async )?function ([a-zA-Z][a-zA-Z0-9_]*)\s*\(/', $line, $m) === 1) {
            $current = $m[1];
            $startLine = $number;
            $depth = 0;
            $body = [];
        }

        continue;
    }

    $body[] = $line;
    $depth += substr_count($line, '{') - substr_count($line, '}');

    if ($depth <= 0 && count($body) > 2) {
        $text = implode("\n", $body);
        $probeCount++;
        inspect($current, $startLine, $text, $findings);

        $current = null;
    }
}

/**
 * The catalogue lists every probe, and the two must agree.
 *
 * Matching the declarations is not enough: a probe declared but never registered would never
 * run, and a registered name with no declaration would be a broken build. Comparing the two
 * lists is what proves this script is looking at the probes that actually execute.
 */
$declaredNames = [];
foreach ($lines as $index => $line) {
    if (preg_match('/^export (?:async )?function ([a-zA-Z][a-zA-Z0-9_]*)\s*\(/', $line, $m) === 1) {
        $declaredNames[] = $m[1];
    }
}
$registeredNames = [];
if (preg_match('/export const VALUE_PROBES[^\[]*\[([\s\S]*?)\n\];/', $source, $m) === 1) {
    preg_match_all("/name:\s*'([a-zA-Z0-9_]+)'/", $m[1], $names);
    $registeredNames = $names[1];
}

$notRegistered = array_values(array_diff($declaredNames, $registeredNames));
$notDeclared = array_values(array_diff($registeredNames, $declaredNames));

printf("%d probe functions parsed; %d registered in VALUE_PROBES\n", count($declaredNames), count($registeredNames));

if ($notRegistered !== []) {
    printf("  declared but NOT registered (never runs): %s\n", implode(', ', $notRegistered));
}
if ($notDeclared !== []) {
    fwrite(STDERR, '  registered with NO declaration (broken): '.implode(', ', $notDeclared)."\n");
    exit(1);
}

if ($probeCount < 15) {
    fwrite(STDERR, "only parsed {$probeCount} bodies; the brace matching is probably wrong\n");
    exit(1);
}

// ---------------------------------------------------------------------------
// The part that actually decides the verdict: HOW MANY RULES each probe feeds.
//
// A shape on its own is not a defect. `permissions` awaits a Promise and `audioOffline`
// awaits `startRendering()` because there is no synchronous way to read either — that is what
// the APIs are, not a mistake. The question that matters is the one the `uaClientHints`
// bug turned on:
//
//     how many checks go dark when one property is replaced?
//
// Measured against `EnvironmentConsistency` by counting how many rules read each probe's
// claim key. A probe read by ZERO rules cannot silence a check — silencing it only changes
// the claim digest, so the device derives a DIFFERENT KEY, which is itself the signal and is
// exactly the right behaviour for a probe that answers "which device is this". A probe read
// by three rules is the `uaClientHints` shape and must be defended in its own right.
// ---------------------------------------------------------------------------

$rulesFile = $root.'src/Rules/EnvironmentConsistency.php';
$confidenceFile = $root.'src/Scoring/ConfidenceScorer.php';

if (! is_file($rulesFile) || ! is_file($confidenceFile)) {
    fwrite(STDERR, "cannot find the rule engine; run this audit from the package root\n");
    exit(1);
}

$ruleSource = (string) file_get_contents($rulesFile);
$confidenceSource = (string) file_get_contents($confidenceFile);

printf("\n%-24s %8s %8s  %s\n", 'PROBE', 'RULES', 'COVERAGE', 'verdict');
printf("%s\n", str_repeat('-', 78));

$multiRule = [];

/**
 * What happens when the probe is stubbed, per probe, measured rather than assumed.
 *
 * The rule count alone is not the verdict, and treating it as one is how this audit would
 * have cried wolf on `stackDepth`.
 *
 * `stackDepth` reads `error.stack` and counts the lines, and `Error.prepareStackTrace` is a
 * single-property assignment:
 *
 *     Error.prepareStackTrace = () => 'x'
 *
 * which made the stack one line, which was OUTSIDE the plausible range, which made
 * `stack_depth_anomalous` FIRE. That was the rule catching the tamper, not the tamper switching
 * the rule off. (The probe and its rule were removed in round 2, notes/25 STD-3: in V8 the
 * depth is always `Error.stackTraceLimit + 1`, so it carried no information. The lesson about
 * direction stands.) The direction is the whole difference: a probe whose stub produces an
 * implausible value is a tripwire, and counting it as a bypass would send someone to "fix" a
 * check that is already working.
 *
 * So each multi-rule probe is classified by what its rules do with a bad value:
 *
 *  - `silence` — the rule cannot fire without the value, so removing it disables detection.
 *    This is the dangerous direction and the only one that needs a code change.
 *  - `trip`    — the rule fires on an implausible value, so removing it is self-punishing.
 *  - `mixed`   — some rules each way.
 */
$DIRECTION = [
    // Read before anything stubbable, each field in its own guard, with the comment saying
    // so. Fixed 2026-09-29 after the single-property bypass was found.
    'uaClientHints' => ['silence', 'brands/mobile/platform are read FIRST, each in its own guard, and only then is the high-entropy call made — so stubbing it cannot take the cheap fields with it'],

    // No `await`, no early return, no catch: a synchronous object literal, so there is no
    // one-property stub that silences it. `navigator.userAgent = 'x'` changes ONE field and
    // therefore a SUBSET of the rules, which is the ordinary case for every spoofer.
    'environment' => ['silence', 'synchronous object literal with no await, early return or catch — one property changes one field, and therefore a subset of the rules'],

    // The five below were the audit's backlog (notes/25 §3, notes/26). Each was classified by reading the
    // rules that read it, on 2026-10-31. The count above is occurrences of the claim key, not rules.

    // The marks are properties the engine puts on the errors IT creates; a page script cannot remove them,
    // only rewrite the claim. A rewritten engine trips `ua_vs_engine` / `engine_vs_ch_header` against the
    // User-Agent and the Sec-CH-UA header; absent marks silence those two but also drop the
    // protected-Gecko excuse, which makes the font, screen and GPU rules stricter, not looser.
    'engineIdentity' => ['mixed', 'engine marks cannot be removed from engine-made errors; forging them against the UA or Sec-CH-UA trips ua_vs_engine / engine_vs_ch_header, and absent marks remove the privacy-mode excuses'],

    // `workerScope`: `window.Worker = undefined` makes the probe unavailable('no-worker') and silences every
    // worker_vs_window_* and *_realm_mismatch rule together. Rewriting a VALUE (the page side) trips them,
    // because the worker realm is out of a page script's reach. Deletion costs only the confidence
    // coverage; no rule fires on "no Worker in a desktop engine". Open item: such a rule.
    'workerScope' => ['silence', 'deleting Worker leaves the probe unavailable and silences the eight page-versus-worker comparisons (coverage drops, no rule trips); a rewritten page value trips them'],

    // `permissions`: a stub that rejects, or answers with a non-enumerated word, trips
    // `notification_permission_nonstandard`; a stub that rejects silences `notification_permission_vs_query`
    // (it needs `prompt` and `denied`), which is the headless pair rather than a conformance rule.
    'permissions' => ['mixed', 'a non-enumerated answer trips notification_permission_nonstandard; a rejecting stub silences notification_permission_vs_query (the headless pair)'],

    // `audioReadback`: one rule (`audio_readback_perturbed`, weight 4) reads three fields of one signal.
    // The thing it flags is noise on the read-back, so a noised value trips it; deleting
    // OfflineAudioContext makes the probe unavailable and costs only that weight-4 rule.
    'audioReadback' => ['mixed', 'noised or forged read-back values trip audio_readback_perturbed; deleting OfflineAudioContext silences that single weight-4 rule'],

    // `gpu`: WebGL1 and WebGL2 are read separately (`gpu_webgl_params_mismatch`), the renderer is checked
    // against the OS and the WebGPU vendor, and the limits against the specification minima. Patching one
    // context's getParameter trips the mismatch; removing WebGL leaves the probe unavailable and silences
    // the renderer rules (the matcher then loses the `gpu` component, which is a coverage cost).
    'gpu' => ['mixed', 'patching one WebGL context trips gpu_webgl_params_mismatch and the renderer rules; removing WebGL silences the renderer rules at a coverage cost'],

    // `cssMedia`: read by `touch_vs_pointer_media` (6) and `media_hover_unanswered` (15). A matchMedia stub
    // answering false trips the hover rule (both complementary hover queries unmatched); deleting or
    // throwing matchMedia yields 'x' per query and silences both. Open item: no rule fires on "no
    // matchMedia in a desktop engine".
    'cssMedia' => ['mixed', 'an always-false matchMedia trips media_hover_unanswered; a throwing or deleted matchMedia answers x and silences it and touch_vs_pointer_media'],

    // `intl`: read by the two time-zone/language rules only (weights 4 and 6). Hiding the zone silences them,
    // but the same stub is what `tz_intl_vs_date`, `worker_vs_window_timezone` and the lie battery on `Intl`
    // exist to catch, so the cheap rules are not the only defence of the zone.
    'intl' => ['silence', 'a hidden zone silences tz_vs_lang_region (4) and tz_utc_vs_language_region (6); the stub itself trips tz_intl_vs_date, worker_vs_window_timezone and the Intl lie battery'],

    // `fontFaces`: always-resolving `FontFace.load` is caught by the honesty gate (sentinel family) and the
    // probe becomes unavailable; always-rejecting reports zero fonts and trips fonts_single_family_desktop
    // on a Windows or macOS User-Agent; deleting `FontFace` is unavailable('no-font-loading').
    // `fontFallback`: read by `render_surfaces_stubbed` only (with `fontMetrics` and `gpu`). Deleting the
    // measuring element's API leaves the probe unavailable and silences that rule at a coverage cost (weight
    // 422); forging font-dependent widths needs a layout engine, or a per-font width table consistent with
    // `fontMetrics`, `textMetrics` and `fontFaces`, which a one-property stub cannot supply.
    'fontFallback' => ['silence', 'an unavailable probe silences render_surfaces_stubbed at a coverage cost; forged widths must also agree with fontMetrics, textMetrics and fontFaces'],

    'fontFaces' => ['mixed', 'always-reject trips fonts_single_family_desktop; always-resolve is caught by the sentinel honesty gate; deleting FontFace silences fonts_vs_ua_os and fonts_single_family_desktop'],

];

foreach ($registeredNames as $name) {
    $quoted = "'{$name}'";
    $rules = substr_count($ruleSource, $quoted);
    $coverage = substr_count($confidenceSource, $quoted);

    if ($rules === 0) {
        $verdict = 'feeds no check - silencing it only changes the device key';
    } elseif ($rules === 1) {
        $verdict = 'feeds ONE check - losing it costs that check, and nothing else';
    } else {
        $direction = $DIRECTION[$name][0] ?? 'UNCLASSIFIED';
        $verdict = sprintf('feeds %d checks - %s', $rules, $direction);
        $multiRule[$name] = ['rules' => $rules, 'direction' => $direction];
    }

    printf("%-24s %8d %8d  %s\n", $name, $rules, $coverage, $verdict);
}

// ---------------------------------------------------------------------------

function inspect(string $name, int $line, string $text, array &$findings): void
{
    // Strip line comments before looking for shapes: a docblock that says "await" or a
    // comment showing an empty `catch {}` would otherwise be reported as code, and a guard
    // that reports prose is a guard nobody reads.
    $code = (string) preg_replace('#^\s*(//|\*|/\*).*$#m', '', $text);

    if (preg_match('/\bawait\b/', $code) === 1) {
        $findings[] = [
            'probe' => $name,
            'line' => $line,
            'shape' => 'awaits inside the probe',
            'why' => 'A stubbed or never-resolving Promise leaves the value unset, and every rule that reads it goes quiet together. This is the `uaClientHints` shape.',
            'snippet' => firstLineMatching($code, ['await']),
        ];
    }

    if (preg_match('/catch\s*(\([^)]*\))?\s*\{\s*\}/', $code) === 1) {
        $findings[] = [
            'probe' => $name,
            'line' => $line,
            'shape' => 'swallows an exception with an empty catch',
            'why' => 'A throwing probe and an absent probe are indistinguishable afterwards, so a patched environment can hide behind a probe that "failed".',
            'snippet' => firstLineMatching($code, ['catch']),
        ];
    }

    // A `return` whose expression is a bare optional chain or a ternary on an absent value:
    // the caller cannot tell "absent" from "attacker removed it".
    if (preg_match('/return\s+[^;]*\?\?/', $code) === 1) {
        $findings[] = [
            'probe' => $name,
            'line' => $line,
            'shape' => 'defaults a missing value with ??',
            'why' => 'Usually correct — most probes SHOULD degrade to null. Reported so each one is confirmed to be an expected absence rather than a masking of an attacker-removed property.',
            'snippet' => firstLineMatching($code, ['??']),
        ];
    }
}

// ---------------------------------------------------------------------------

$grouped = [];
foreach ($findings as $finding) {
    $grouped[$finding['shape']][] = $finding;
}

if ($grouped === []) {
    echo "\nNo candidate shape found in any probe.\n";
}

foreach ($grouped as $shape => $rows) {
    printf("\n%s  (%d)\n", strtoupper($shape), count($rows));
    printf("%s\n", str_repeat('-', strlen(strtoupper($shape)) + 8));

    foreach ($rows as $row) {
        printf("\n  %s  (line %d)\n", $row['probe'], $row['line']);
        printf("    why: %s\n", $row['why']);
        if ($row['snippet'] !== null) {
            printf("    at:  %s\n", trim($row['snippet']));
        }
        if (isset($multiRule[$row['probe']])) {
            printf(
                "    VERDICT: feeds %d checks - %s\n",
                $multiRule[$row['probe']]['rules'],
                $multiRule[$row['probe']]['direction']
            );
        } else {
            printf("    VERDICT: feeds no check - not a single-point bypass for any rule.\n");
        }
    }
}

// The verdict is the UNCLASSIFIED multi-rule set, not the shape count.
$unclassified = array_filter($multiRule, static fn (array $row): bool => $row['direction'] === 'UNCLASSIFIED');

echo "\n";
foreach ($multiRule as $name => $row) {
    printf("  %-20s %d checks, %-10s %s\n", $name, $row['rules'], $row['direction'], $DIRECTION[$name][1] ?? '');
}

if ($unclassified === []) {
    $silence = array_keys(array_filter($multiRule, static fn (array $row): bool => $row['direction'] === 'silence'));
    echo "\nEvery probe that feeds more than one check has been classified, and each\n";
    echo "classification says what a one-property stub actually DOES to it.\n\n";
    printf("Classified `silence` (a one-property stub removes checks' ability to fire): %s.\n", implode(', ', $silence));
    echo "Each note above names what defends it; they are not a defect-free result. A `silence`\n";
    echo "entry whose defence is only \"coverage drops\" (workerScope) is the open backlog for a rule.\n\n";
    echo "A PASS here is NOT a claim that the probes are unbypassable. It is the narrower\n";
    echo "claim that no probe feeding several checks is unclassified. The real evidence is a live\n";
    echo "stealth spoofer against real engines (see tools/capture and tests/Unit).\n";
    exit(0);
}

printf(
    "\n%d probe(s) feed more than one check and are UNCLASSIFIED: %s\n",
    count($unclassified),
    implode(', ', array_keys($unclassified))
);
echo "Add each to \$DIRECTION in this file with what a one-property stub actually DOES to\n";
echo "it - silenced, tripped, or mixed. Do not add it as 'silence' without reading the rule.\n";

exit(1);

/** The first line of $text containing any of $needles, trimmed. */
function firstLineMatching(string $text, array $needles): ?string
{
    foreach (explode("\n", $text) as $line) {
        foreach ($needles as $needle) {
            if (str_contains($line, $needle)) {
                return $line;
            }
        }
    }

    return null;
}

<?php

declare(strict_types=1);

/**
 * DEMO — the standalone fingerprinting package, with no framework and no application.
 *
 * ## What this proves, and what it is not
 *
 * It runs the REAL ported engine — the same 26 rules, the same scorer, the same
 * canonicaliser — against fixture claim sets and prints what came out. It is not a
 * simulation and it does not stand in for anything: if the rules stopped working, this
 * output would change, which is why `tools/golden-check.php` asserts fixed answers for the
 * same claim sets (the application runs this same engine since 2026-10-21).
 *
 * The claim sets are FIXTURES. They are labelled as such in the output, because a demo that
 * printed invented numbers and called them measurements would be exactly the kind of thing
 * §4.4 Category A prohibits. A real collection would come from a browser; the engine cannot
 * tell the difference and does not need to.
 *
 * ## The one thing this file demonstrates that a unit test cannot
 *
 * That the whole thing runs on a bare SPL autoloader with no container, no config file and
 * no Composer. It prints the load-graph check as part of its output, so the claim is visible
 * in the demo rather than in a separate script someone has to remember to run.
 *
 * Run: php demo/standalone-demo.php
 */
$root = dirname(__DIR__);

// The ONLY include. Thirteen lines of spl_autoload_register, and no framework.
require __DIR__.'/../src/autoload.php';

use DeviceId\Canonicaliser;
use DeviceId\CheckRegistry;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Scoring\ConfidenceScorer;
use DeviceId\Scoring\VerdictScorer;
use DeviceId\Settings;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;

$line = static function (string $title): void {
    echo "\n".str_repeat('=', 78)."\n".$title."\n".str_repeat('=', 78)."\n";
};
$sub = static function (string $title): void {
    echo "\n".$title."\n".str_repeat('-', strlen($title))."\n";
};

// ---------------------------------------------------------------------------
$line('1. Is a framework present?');

$loaded = array_merge(get_declared_classes(), get_declared_interfaces(), get_declared_traits());

// `str_starts_with` rather than a regex. The regex version was written as
// `'...\\InstalledVersions$/'` in a SINGLE-quoted PHP string, where `\\` is already a literal
// backslash — so the pattern reached PCRE as `\InstalledVersions` and `\I` is not a valid
// escape. It warned once per loaded class and returned false for everything, which would
// have printed "framework symbols: 0" for the wrong reason: a broken check that always
// passes is worse than no check.
$prefixes = ['Illuminate\\', 'Symfony\\', 'Psr\\', 'Laravel\\', 'Monolog\\', 'Composer\\InstalledVersions'];
$frameworkish = array_values(array_filter(
    $loaded,
    static fn (string $class): bool => (bool) array_filter(
        $prefixes,
        static fn (string $prefix): bool => str_starts_with($class, $prefix)
    )
));

printf("  classes loaded .......... %d\n", count($loaded));
printf("  framework symbols ....... %d\n", count($frameworkish));
printf("  container / config ...... %s\n", function_exists('app') ? 'PRESENT' : 'absent');
printf("  Composer required ....... no\n");
foreach ($frameworkish as $symbol) {
    printf("  UNEXPECTED .............. %s\n", $symbol);
}
echo "\n  This file required ONE thing: src/autoload.php. No bootstrap, no config, no container.\n";

// ---------------------------------------------------------------------------
$line('2. Configuration handed to the engine');

Config::use([
    'fingerprint' => [
        'score_divisor' => 40,
        'bands' => ['elevated' => 40, 'challenge' => 60, 'block' => 80],
        'enabled' => true,
    ],
    'transport_integrity' => ['ja4_profiles' => []],
    'session' => ['cookie' => 'nutricompare_session'],
]);

printf("  score_divisor ........... %d\n", Config::int('fingerprint.score_divisor', 0));
printf("  band: block ............. %d\n", Config::int('fingerprint.bands.block', 0));
printf("  registered checks ....... %d\n", count(CheckRegistry::codes()));
echo "\n  Absent keys fall back to the caller's default, and a wrong-typed value does NOT\n";
echo "  coerce: bool() on the string 'false' is not false.\n";

// ---------------------------------------------------------------------------
$line('3. The checks, and their weights');

$families = [];
foreach (CheckRegistry::describe() as $code => $meta) {
    $families[$meta['family']][] = [$code, $meta['default_weight']];
}
foreach ($families as $family => $rows) {
    echo "\n  [{$family}]\n";
    foreach ($rows as [$code, $weight]) {
        printf("    %-46s %3d\n", $code, $weight);
    }
}

echo "\n  A weight of 0 SILENCES a check. The heaviest is 40 and the block band is 80,\n";
echo "  so no single check can block a device on its own: a device has to contradict\n";
echo "  itself in two independent ways.\n";

// ---------------------------------------------------------------------------
$line('4. Running the engine on fixture claim sets');

/**
 * Fixtures, not measurements. Each is a claim set of the shape a browser's collector
 * produces; the engine cannot tell the difference and does not need to. They live in
 * `fixtures.php` so `tools/golden-check.php` asserts fixed answers for the same claim sets.
 *
 * @var array<string, array<string, mixed>> $fixtures
 */
$fixtures = require __DIR__.'/fixtures.php';

$rules = new EnvironmentConsistency;
$scorer = new VerdictScorer($rules);
$confidencer = new ConfidenceScorer;

// The host's view of its own overrides, so the effective weight beside each finding is the
// one that actually fired rather than the shipped default.
$settings = Settings::fromArray([
    'check_weights' => (array) Config::raw('fingerprint.constraint_weights', []),
]);

foreach ($fixtures as $label => $claims) {
    $sub($label);

    $transport = new TransportIntegrityResult;
    $confidence = $confidencer->score($claims, $transport);
    $verdict = $scorer->score($claims, $transport, confidence: $confidence);

    printf("  claim count ............. %d\n", count($claims));
    printf("  confidence .............. %d (earned %d of %d expected)\n", $confidence->score, $confidence->earned, $confidence->expected);
    printf("  what it got wrong ....... %s\n", $verdict->reasons === [] ? '(nothing)' : implode(', ', $verdict->reasons));
    printf("  total weight ............ %d\n", $verdict->totalWeight());
    printf("  score ................... %d\n", $verdict->score);
    printf("  band .................... %s\n", $verdict->band);

    // `reasons` is a LIST of stable codes, not a map. `disagreements` is a list of weights.
    // Two earlier drafts read `array_keys()` off both, which yields `[0]` and printed "0" as
    // though a code had been found when none had — and a demo that reports a finding that
    // does not exist is worse than a demo that crashes.
    // `disagreements` holds the OCCURRENCE COUNT per code, not a weight — `lied_os` shows 1
    // while the effective weight behind `total weight 20` is 20. Printing the count under
    // the heading "weight" would have been a wrong number on screen, so it is labelled for
    // what it is and the effective weight is looked up from the registry beside it.
    foreach ($verdict->reasons as $index => $code) {
        $effective = CheckRegistry::weightFor($code, $settings);
        $occurrences = $verdict->disagreements[$index] ?? 0;
        // `%d` on a value PHPStan cannot narrow is a cast it dislikes. The value is a count
        // of occurrences and it is an int by construction — `Disagreement` is
        // `list<int>` — so narrowing it here is the assertion, not a workaround.
        printf(
            "      %-44s seen %dx, effective weight %d\n",
            $code,
            is_int($occurrences) ? $occurrences : 0,
            $effective
        );
    }

    if ($verdict->reasons !== []) {
        echo "\n      Each one is a claim contradicting another claim. MISSING data is never\n";
        echo "      evidence: the empty claim set below scores 0 and passes, because there is\n";
        echo "      nothing to disagree with.\n";
    }
}

// ---------------------------------------------------------------------------
$line('5. The digest, which is what a device key is built from');

foreach ($fixtures as $label => $claims) {
    $digest = Canonicaliser::digest($claims);
    printf("\n  %s\n", $label);
    printf("    sha256 ................. %s\n", $digest);
    printf("    canonical form, %4d b .. %s%s\n", strlen(Canonicaliser::claims($claims)), substr(Canonicaliser::claims($claims), 0, 96), strlen(Canonicaliser::claims($claims)) > 96 ? '…' : '');
}

echo "\n  Canonicalisation is type-tagging and order-preserving. A device reporting\n";
echo "  hardwareConcurrency as 1 and one reporting \"1\" derive DIFFERENT keys, and a\n";
echo "  nested object is sorted recursively, so the same environment always hashes the\n";
echo "  same way regardless of the order the browser happened to enumerate it.\n";

// ---------------------------------------------------------------------------
$line('6. Silencing a check, with no application');

$silenced = CheckRegistry::weightFor('lied_os', $settings->with('check_weights', ['lied_os' => 0]));
$on = CheckRegistry::weightFor('lied_os', $settings);
printf("  lied_os, no override .... %d\n", $on);
printf("  lied_os, silenced ....... %d\n", $silenced);
printf("  -> an operator can switch one check off without a deploy and without a rebuild.\n");

echo "\n".str_repeat('=', 78)."\n";
echo "  STANDALONE DEMO COMPLETE - no framework, no container, no application.\n";
echo "  The answers are pinned by tools/golden-check.php; the application runs this same engine.\n";
echo str_repeat('=', 78)."\n";

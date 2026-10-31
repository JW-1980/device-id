<?php

declare(strict_types=1);

/**
 * Golden check: the engine's answers for fixed claim sets, pinned to fixed values.
 *
 * ## Why this exists (2026-10-21, research/fingerprinting/notes/26)
 *
 * Until 2026-10-21 the engine existed twice — in the Laravel application and, generated from
 * it, in this package — and the gates were DIFFERENTIAL: they compared the two copies. Since
 * the one-engine migration the application runs THIS package's engine, so there is nothing to
 * compare against, and a comparison of two copies never proved either was right anyway
 * (notes/17). What remains worth asserting is that the engine's answers do not change by
 * accident: a rule, weight, band, confidence or canonical-format change must change this file
 * consciously, in the same commit, where a reviewer sees it.
 *
 * ## What is pinned
 *
 * For every fixture claim set, run through the engine on a bare SPL autoloader with the fixed
 * configuration below:
 *
 * - the disagreement list, in order, as `code:weight`, and a hash of its detail sentences;
 * - the verdict's reasons, total weight, score and band;
 * - the confidence score, earned, expected and the missing-probe list;
 * - the canonical digest (`Canonicaliser::digest()`), which device keys are derived from;
 * - the derived keys (`Keys\DeviceKeyDeriver`: browser key, hardware key, salt version,
 *   coverage, protected flag, a hash of the quantised components, the untrusted list, and the
 *   single device key) under the fixed test secret {@see GOLDEN_KEY_SECRET};
 * - for the captured integrity blocks, the effective integrity finding codes.
 *
 * The fixtures: the claim sets captured from real engines in
 * `tests/Fixtures/fingerprint/claims-*.json`, the honest integrity captures in
 * `tests/Fixtures/fingerprint/honest-integrity.json` (each engine's tier-1, tier-2 and merged
 * identify forms, built as tests/Unit/Security/IntegrityFindingsTest.php builds them), and the
 * demo's labelled claim sets (`demo/fixtures.php`). The repository fixtures are read from the
 * repository root this package lives in; a missing fixture is a FAILURE, never a skip.
 *
 * ## Where the expected values came from
 *
 * Recorded from a real run on 2026-10-21 with
 *
 *     php tools/golden-check.php --record
 *
 * after the one-engine migration, on the package engine that is token-identical (outside its
 * configuration call sites) to the application engine whose differential parity gate passed
 * the same day. They are what the engine DID, not what anyone believes it should do; the
 * PHPUnit suites (tests/Unit/Security, tests/Feature/Security) assert intended behaviour.
 *
 * ## It can fail, and proves it
 *
 * Two self-checks run on every invocation: a deliberately altered expectation must be
 * reported as a mismatch, and re-running the engine with one weight changed must produce a
 * mismatch against the recorded values. A gate that cannot fail is worse than no gate.
 *
 * Usage:
 *   php tools/golden-check.php            # compare; exit 1 on any mismatch
 *   php tools/golden-check.php --record   # print the current answers as PHP
 */
require __DIR__.'/../src/autoload.php';

use DeviceId\Canonicaliser;
use DeviceId\Keys\DeviceKeyDeriver;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Rules\IntegrityFindings;
use DeviceId\Scoring\ConfidenceScorer;
use DeviceId\Scoring\VerdictScorer;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;

/**
 * The fixed configuration every answer below was recorded under: the shipped bands and
 * divisor, the shipped weights (no overrides), no JA4 profiles.
 *
 * @param  array<string, int>  $weightOverrides
 */
function golden_configure(array $weightOverrides = []): void
{
    Config::reset();
    Config::use([
        'fingerprint' => [
            'score_divisor' => 40,
            'bands' => ['elevated' => 40, 'challenge' => 60, 'block' => 80],
            'constraint_weights' => $weightOverrides,
            'enabled' => true,
            'device_key_secret' => GOLDEN_KEY_SECRET,
        ],
        'transport_integrity' => ['ja4_profiles' => []],
    ]);
}

/**
 * The device-key secret the key columns below were derived under. A fixed TEST value, never a
 * deployment's: keys are HMACs under the secret, so pinning them pins the derivation (claim
 * stabilisation, component quantisation, canonical form, HMAC scoping) and nothing secret.
 */
const GOLDEN_KEY_SECRET = 'golden-check-fixed-test-secret-0123456789abcdef';

/**
 * @return array<string, mixed>
 */
function golden_decode(string $path): array
{
    if (! is_file($path)) {
        throw new RuntimeException("fixture missing: {$path}");
    }
    $decoded = json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
    if (! is_array($decoded)) {
        throw new RuntimeException("fixture is not a JSON object: {$path}");
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
}

/**
 * Every fixture claim set, by a stable label.
 *
 * @return array<string, array<string, mixed>>
 */
function golden_fixtures(): array
{
    $fixtureDirectory = dirname(__DIR__).'/tests/Fixtures/fingerprint';
    $sets = [];

    $claimFiles = glob($fixtureDirectory.'/claims-*.json');
    if ($claimFiles === false || $claimFiles === []) {
        throw new RuntimeException("no claims-*.json fixtures under {$fixtureDirectory}");
    }
    sort($claimFiles);
    foreach ($claimFiles as $file) {
        $sets['captured '.basename($file, '.json')] = golden_decode($file);
    }

    $integrity = golden_decode($fixtureDirectory.'/honest-integrity.json');
    $engines = $integrity['engines'] ?? null;
    if (! is_array($engines) || $engines === []) {
        throw new RuntimeException('honest-integrity.json has no engines');
    }
    foreach ($engines as $engine => $capture) {
        $sync = is_array($capture) && is_array($capture['sync'] ?? null) ? $capture['sync'] : null;
        $deferred = is_array($capture) && is_array($capture['deferred'] ?? null) ? $capture['deferred'] : null;
        if ($sync === null || $deferred === null
            || ! is_array($sync['findings'] ?? null) || ! is_array($deferred['findings'] ?? null)
            || ! is_array($sync['data'] ?? null) || ! is_array($deferred['data'] ?? null)) {
            throw new RuntimeException("honest-integrity.json: {$engine} lacks sync/deferred findings and data");
        }
        $sets["integrity {$engine} tier1"] = ['integrity' => $sync];
        $sets["integrity {$engine} tier2"] = ['integrity' => $deferred];
        // The identify path's merged form (index.ts `mergeIntegrity`): findings concatenated,
        // deferred data winning.
        $sets["integrity {$engine} identify"] = ['integrity' => [
            'findings' => [...$sync['findings'], ...$deferred['findings']],
            'data' => array_replace($sync['data'], $deferred['data']),
        ]];
    }

    /** @var array<string, array<string, mixed>> $demo */
    $demo = require dirname(__DIR__).'/demo/fixtures.php';
    foreach ($demo as $label => $claims) {
        $sets['demo '.$label] = $claims;
    }

    return $sets;
}

/**
 * The engine's answer for one claim set, as plain data.
 *
 * @param  array<string, mixed>  $claims
 * @return array<string, mixed>
 */
function golden_answer(array $claims): array
{
    $transport = new TransportIntegrityResult;
    $confidence = (new ConfidenceScorer)->score($claims, $transport);
    $verdict = (new VerdictScorer(new EnvironmentConsistency))->score($claims, $transport, confidence: $confidence);

    $disagreements = [];
    $details = [];
    foreach ($verdict->disagreements as $disagreement) {
        $disagreements[] = $disagreement['code'].':'.$disagreement['weight'];
        $details[] = $disagreement['detail'];
    }

    $integrity = IntegrityFindings::effective($claims);

    // Key derivation, as `FingerprintIngest` runs it (global scope, no organisation).
    $deriver = new DeviceKeyDeriver;
    $keys = $deriver->keys($claims, $transport);
    $legacy = $deriver->derive($claims);

    return [
        'disagreements' => $disagreements,
        'details_sha256' => substr(hash('sha256', implode("\n", $details)), 0, 16),
        'reasons' => $verdict->reasons,
        'total_weight' => $verdict->totalWeight(),
        'score' => $verdict->score,
        'band' => $verdict->band,
        'confidence' => [$confidence->score, $confidence->earned, $confidence->expected],
        'missing' => $confidence->missing,
        // code:provenance (client, server or both), in the order the engine reports them.
        'integrity_codes' => array_map(
            static fn (string $code, string $provenance): string => $code.':'.$provenance,
            array_keys($integrity),
            array_values($integrity),
        ),
        'digest' => Canonicaliser::digest($claims),
        // browser key, hardware key, salt version, coverage, protected — null when no keys.
        'keys' => $keys === null ? null : [$keys->browserKey, $keys->hardwareKey, $keys->saltVersion, $keys->coverage, $keys->protected],
        'components_sha256' => $keys === null ? null : hash('sha256', (string) json_encode($keys->components, JSON_THROW_ON_ERROR)),
        'untrusted' => $keys === null ? null : $keys->untrusted,
        'device_key' => $legacy?->key,
    ];
}

/**
 * Every difference between the recorded and the produced answers, as readable lines.
 *
 * @param  array<string, array<string, mixed>>  $expected
 * @param  array<string, array<string, mixed>>  $actual
 * @return list<string>
 */
function golden_compare(array $expected, array $actual): array
{
    $mismatches = [];
    foreach ($expected as $label => $fields) {
        if (! array_key_exists($label, $actual)) {
            $mismatches[] = "{$label}: no longer produced";

            continue;
        }
        foreach ($fields as $field => $value) {
            $got = $actual[$label][$field] ?? null;
            if ($got !== $value) {
                $mismatches[] = sprintf(
                    '%s: %s expected %s, got %s',
                    $label,
                    $field,
                    (string) json_encode($value, JSON_UNESCAPED_SLASHES),
                    (string) json_encode($got, JSON_UNESCAPED_SLASHES),
                );
            }
        }
        foreach (array_diff(array_keys($actual[$label]), array_keys($fields)) as $extra) {
            $mismatches[] = "{$label}: {$extra} is produced but not pinned";
        }
    }
    foreach (array_diff(array_keys($actual), array_keys($expected)) as $label) {
        $mismatches[] = "{$label}: produced but not pinned";
    }

    return $mismatches;
}

/**
 * The engine's answers for every fixture, under the fixed configuration plus overrides.
 *
 * @param  array<string, int>  $weightOverrides
 * @return array<string, array<string, mixed>>
 */
function golden_run(array $weightOverrides = []): array
{
    golden_configure($weightOverrides);
    $out = [];
    foreach (golden_fixtures() as $label => $claims) {
        $out[$label] = golden_answer($claims);
    }
    Config::reset();

    return $out;
}

/**
 * A value as short-array PHP, lists inline, so a recorded answer is one reviewable line.
 */
function golden_literal(mixed $value): string
{
    if (! is_array($value)) {
        return var_export($value, true);
    }

    $isList = array_is_list($value);
    $items = [];
    foreach ($value as $key => $item) {
        $items[] = ($isList ? '' : var_export($key, true).' => ').golden_literal($item);
    }

    return '['.implode(', ', $items).']';
}

try {
    $actual = golden_run();
} catch (Throwable $e) {
    fwrite(STDERR, 'GOLDEN: FAIL — '.$e::class.': '.$e->getMessage()."\n");
    exit(1);
}

if (in_array('--record', $argv, true)) {
    // One field per line, lists inline, so a conscious change to the engine shows up in
    // review as a one-line diff per changed answer.
    echo "const GOLDEN = [\n";
    foreach ($actual as $label => $fields) {
        echo '    '.var_export($label, true)." => [\n";
        foreach ($fields as $field => $value) {
            echo '        '.var_export($field, true).' => '.golden_literal($value).",\n";
        }
        echo "    ],\n";
    }
    echo "];\n";
    exit(0);
}

// Recorded 2026-10-21 with: php tools/golden-check.php --record
// Re-recorded 2026-10-30 after the collector merge. Changed answers, all in `confidence` and
// `missing` (no disagreement, score, band, digest or key changed): the shipped catalogue is now
// exactly the merged collector's probe set (+tier1:objectShape, removedApiBoundary, +tier2:
// buildFingerprint, keyboardLayout, webrtc, behavior; expected 10930 -> 11730). The captured claim
// sets pre-date the webrtc and behavior probes, so those two read as missing in them (Chromium
// confidence stays 74, Firefox 74 -> 73, WebKit 75 -> 74); the empty and declined sets stay at 1.
// Re-recorded 2026-10-30 after the false-positive fixes (commit "Fix false positives..."). Changed
// answers: the seven headless-Chromium captures lose `plugins_vs_ua:12` (57 -> 45, score 76 -> 68,
// band stays `challenge`): they report `pdfViewerEnabled: false`, which a desktop Chrome with its
// PDF viewer switched off reports as well, so an empty plugin list there is no longer a finding;
// `ua_headless_token:30` + `notification_permission_vs_query:15` still catch them. Nothing else moved.
// Re-recorded 2026-10-30 for probe set 4 (commit "Add automation marks, ..."). Changed answers: only
// `components_sha256`, in all 22 sets. The stored component map gained three keys (`keyboard`,
// `gpuCaps`, `codecsHw`; null or a class string), which changes the hash of the map; no disagreement,
// score, band, digest, key or confidence moved (the new components are not expected for coverage and
// are in neither key).
// Re-recorded 2026-10-30 after dropping the `canvasGeometry` probe (speed commit). Changed answers, all
// in `confidence` and `missing`: the catalogue lost `tier2:canvasGeometry` (weight 364), so `expected`
// 11730 -> 11366, `earned` drops by 364 in every set that carried the probe, and the probe leaves every
// `missing` list. The Chromium captures stay at 74; the partial set that moved 17 -> 18 did so because
// the same fixed gap is a smaller share of a smaller total. No disagreement, score, band, digest or key
// moved: nothing read the probe except the confidence number.
// Re-recorded 2026-10-31 for the detection wave, step 1 (`webdriver_true` 20). Changed answers: the seven
// headless-Chromium captures gain `webdriver_true:20` (every driven browser carries navigator.webdriver = true):
// total_weight 45 -> 65, score 68 -> 80, band challenge -> block, and details_sha256 and reasons change with it;
// the Firefox capture gains it too (0 -> 20, score 0 -> 39, band stays pass) and the WebKit capture, which
// already carried the documented `lied_os` harness artefact (20 -> 40, score 39 -> 63, pass -> challenge).
// That is the intended effect: UA token + notification pair + self-reported WebDriver are three
// independent self-announcements, none of which blocks alone (max 45). No confidence, key, digest or
// component hash moved.
// Re-recorded 2026-10-31 for probe set 5 (smart signals, the `storageProfile` probe). Changed answers, all in
// `confidence` and `missing`: the catalogue gained `tier2:storageProfile` (weight 50), so `expected` 11366 -> 11416
// in every set, and every captured set that pre-dates the probe reads it as missing (Chromium captures 74 -> 73
// where the 50 points were not already lost to rounding). No disagreement, score, band, digest, key or component
// hash moved: the new rules (`ip_country_vs_locale`, `network_*`, `vm_*`, `emulator_android`,
// `private_mode_with_other_signals`) need network facts or the new probe and are silent on every fixture,
// which is the honest-silent behaviour they are specified to have.
// (configuration: golden_configure() above). Change these only together with the engine
// change that explains them.
const GOLDEN = [
    'captured claims-chromium.colorScheme_dark' => [
        'disagreements' => ['webdriver_true:20', 'notification_permission_vs_query:15', 'ua_headless_token:30'],
        'details_sha256' => '582e221455489e2d',
        'reasons' => ['notification_permission_vs_query', 'ua_headless_token', 'webdriver_true'],
        'total_weight' => 65,
        'score' => 80,
        'band' => 'block',
        'confidence' => [73, 11242, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => 'c0406291ec57f8044ba91f511c2fc9195b35ded42817519c483510751e57015b',
        'keys' => ['49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb', '2abd7695bd8258854039e5d8e49b3e25a5cea53344e2bc10db32a38984724396', 25626, 0.875, false],
        'components_sha256' => 'a1b011cf1c76e4432d931f06fd603a41b2a834bc992b5ff4c1c5ccf28642b67e',
        'untrusted' => [],
        'device_key' => '49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb',
    ],
    'captured claims-chromium.dsf_2' => [
        'disagreements' => ['webdriver_true:20', 'notification_permission_vs_query:15', 'ua_headless_token:30'],
        'details_sha256' => '582e221455489e2d',
        'reasons' => ['notification_permission_vs_query', 'ua_headless_token', 'webdriver_true'],
        'total_weight' => 65,
        'score' => 80,
        'band' => 'block',
        'confidence' => [73, 11242, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => '4058a1feb252c03e00abba8e97149e24628b8508549dc1de1fce6f9cfec94549',
        'keys' => ['49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb', '2abd7695bd8258854039e5d8e49b3e25a5cea53344e2bc10db32a38984724396', 25626, 0.875, false],
        'components_sha256' => 'e890d3b47199c78f41304bc0b7fc6d4e029a8ec997cd1e8b91c1c358c4fd133a',
        'untrusted' => [],
        'device_key' => '49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb',
    ],
    'captured claims-chromium.hasTouch' => [
        'disagreements' => ['webdriver_true:20', 'notification_permission_vs_query:15', 'ua_headless_token:30'],
        'details_sha256' => '582e221455489e2d',
        'reasons' => ['notification_permission_vs_query', 'ua_headless_token', 'webdriver_true'],
        'total_weight' => 65,
        'score' => 80,
        'band' => 'block',
        'confidence' => [73, 11242, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => 'ffe5a12f5af545f393d3a31c24349a634ea3b25600e910c81d3aa15f1078c547',
        'keys' => ['9dfbdd230df8fdccfdd976120687e50877041b7dae44b7e1b21b92740d50918b', '26422b9bdd4befd152f8756762a977004ff60b33f94042651b326df3ad3b62d0', 25626, 0.875, false],
        'components_sha256' => 'fc6406423aacb4026cf43a7633c789e7c690de1c623f698e87da5455fa0ce859',
        'untrusted' => [],
        'device_key' => '9dfbdd230df8fdccfdd976120687e50877041b7dae44b7e1b21b92740d50918b',
    ],
    'captured claims-chromium' => [
        'disagreements' => ['webdriver_true:20', 'notification_permission_vs_query:15', 'ua_headless_token:30'],
        'details_sha256' => '582e221455489e2d',
        'reasons' => ['notification_permission_vs_query', 'ua_headless_token', 'webdriver_true'],
        'total_weight' => 65,
        'score' => 80,
        'band' => 'block',
        'confidence' => [73, 11242, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => '5fcbeece92dc8ea133adf012336a1fbe2cfb50ef2d8180109c5cd24a3b311beb',
        'keys' => ['49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb', '2abd7695bd8258854039e5d8e49b3e25a5cea53344e2bc10db32a38984724396', 25626, 0.875, false],
        'components_sha256' => 'a1b011cf1c76e4432d931f06fd603a41b2a834bc992b5ff4c1c5ccf28642b67e',
        'untrusted' => [],
        'device_key' => '49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb',
    ],
    'captured claims-chromium.locale_en_US_tz_New_York' => [
        'disagreements' => ['webdriver_true:20', 'notification_permission_vs_query:15', 'ua_headless_token:30'],
        'details_sha256' => '582e221455489e2d',
        'reasons' => ['notification_permission_vs_query', 'ua_headless_token', 'webdriver_true'],
        'total_weight' => 65,
        'score' => 80,
        'band' => 'block',
        'confidence' => [73, 11242, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => 'e188c469d1849dbbdc202ee36ced78e48940c3d9fd289f50e57af295ab446ea7',
        'keys' => ['49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb', '2abd7695bd8258854039e5d8e49b3e25a5cea53344e2bc10db32a38984724396', 25626, 0.875, false],
        'components_sha256' => 'a1b011cf1c76e4432d931f06fd603a41b2a834bc992b5ff4c1c5ccf28642b67e',
        'untrusted' => [],
        'device_key' => '49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb',
    ],
    'captured claims-chromium.reducedMotion' => [
        'disagreements' => ['webdriver_true:20', 'notification_permission_vs_query:15', 'ua_headless_token:30'],
        'details_sha256' => '582e221455489e2d',
        'reasons' => ['notification_permission_vs_query', 'ua_headless_token', 'webdriver_true'],
        'total_weight' => 65,
        'score' => 80,
        'band' => 'block',
        'confidence' => [73, 11242, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => 'd2b52372c0c0ff32b7ec5ddeabfad602c1325bb838dc3e8af895ea486b066dd9',
        'keys' => ['49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb', '2abd7695bd8258854039e5d8e49b3e25a5cea53344e2bc10db32a38984724396', 25626, 0.875, false],
        'components_sha256' => 'a1b011cf1c76e4432d931f06fd603a41b2a834bc992b5ff4c1c5ccf28642b67e',
        'untrusted' => [],
        'device_key' => '49ce808a5489116835ecc403c2866301630fb3f93166361c2700d2a2ffdef2bb',
    ],
    'captured claims-chromium.viewport_1920x1080' => [
        'disagreements' => ['webdriver_true:20', 'notification_permission_vs_query:15', 'ua_headless_token:30'],
        'details_sha256' => '582e221455489e2d',
        'reasons' => ['notification_permission_vs_query', 'ua_headless_token', 'webdriver_true'],
        'total_weight' => 65,
        'score' => 80,
        'band' => 'block',
        'confidence' => [73, 11242, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => '38c49cac956a426c1e58204a6cfe97b90ae219714e5589a42e7cace7bb214f06',
        'keys' => ['e40acc639e444caff66735be30780a36bf79577fbe72a6b4fedf0eaebe1195e1', '2abd7695bd8258854039e5d8e49b3e25a5cea53344e2bc10db32a38984724396', 25626, 0.875, false],
        'components_sha256' => 'b1c5b6ff0d23d65f240ca377c5f8e985ae6f26a181f16a99b36eea2116a727dd',
        'untrusted' => [],
        'device_key' => 'e40acc639e444caff66735be30780a36bf79577fbe72a6b4fedf0eaebe1195e1',
    ],
    'captured claims-firefox' => [
        'disagreements' => ['webdriver_true:20'],
        'details_sha256' => 'cb8b4c2493dee9aa',
        'reasons' => ['webdriver_true'],
        'total_weight' => 20,
        'score' => 39,
        'band' => 'pass',
        'confidence' => [73, 11167, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => '7cf0d18ccb37e422698cbbaf914f5bd801c05cf18a5ca63d9e290b2d706343a1',
        'keys' => ['f909d6f98c6693f8ab9d7b14185fa86df4d2e6ab18b714eb54a301469357307f', '2abd7695bd8258854039e5d8e49b3e25a5cea53344e2bc10db32a38984724396', 25626, 0.786, false],
        'components_sha256' => 'bf258253db28a526bf53f8d73047ae5d82cd63d922805a028c7eb2a1bb6004ce',
        'untrusted' => [],
        'device_key' => 'f909d6f98c6693f8ab9d7b14185fa86df4d2e6ab18b714eb54a301469357307f',
    ],
    'captured claims-webkit' => [
        'disagreements' => ['webdriver_true:20', 'lied_os:20'],
        'details_sha256' => 'c3b4f7cb671b0ff7',
        'reasons' => ['lied_os', 'webdriver_true'],
        'total_weight' => 40,
        'score' => 63,
        'band' => 'challenge',
        'confidence' => [74, 11317, 11416],
        'missing' => ['tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile'],
        'integrity_codes' => [],
        'digest' => '4c52f1557e8e34a09a23d7c8a2f911da21a2c48e15139931060c57fde5cb9582',
        'keys' => ['aa38dee6a4c8de011910a07489906e16eb66f0a24f7278181b72cab26b3630c7', 'c622d5fe4404e6075193a628bf114b769c34555ad5141b0b3b9747abdda7540e', 25626, 0.929, false],
        'components_sha256' => 'bd0e985a4c76416ce02ab8d608d7c15fe57f27f63cc09599598722ef2cc0e237',
        'untrusted' => [],
        'device_key' => 'aa38dee6a4c8de011910a07489906e16eb66f0a24f7278181b72cab26b3630c7',
    ],
    'integrity chromium tier1' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => '3e13fc676e0d3850c9a7d5ada80e2a7bc8d14457e2569a40509dfb3cd0f8a0d7',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'integrity chromium tier2' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => 'b64ab9a39741a04626c4e7d7e5cd06c24730d2dabeb32477ada6522e9bb93a88',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'integrity chromium identify' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => '1a42a20775f681828a69424e59eab9242eb9d52e5ec4337cbf95452b3a04b891',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'integrity firefox tier1' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => 'df7b7f473f368f9866c64b88f3651b6f90f2c728c1976f47c41ca79aaa1cd1ce',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'integrity firefox tier2' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => 'f2a0f0110bbcb3ab5eb6573247b7f2ef1aef8ad98e1905887e30dc4a0030b774',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'integrity firefox identify' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => 'c6d7acbed0c846aa026d6fc2971f5649fdeac18c8af6f67570d224899e0bba52',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'integrity webkit tier1' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => '1262d6ffda34d3a4e97f98fced9c31488dae80e37dc4f8f7f51511b125ed08ad',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'integrity webkit tier2' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => 'c5e0916ba817ab647e20fead7c0a4ccc66dece2a2ac7ee80f380bf7f00c8f4e2',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'integrity webkit identify' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => '3788e4a16211d561c4ce85fafba786b5cb082ef4fb2c08f0d55682572d6ebf57',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
    'demo honest chromium on windows' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [18, 2021, 11416],
        'missing' => ['tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => '701fe7626d54be8dd9a692965bd1cc826ba4f64d5a46ac71b79abf9e460775a9',
        'keys' => ['2de4f3945ea2e14bffb52bfdf3b36c7dbda128aeb260b67e35170bc40ec593c3', null, 25626, 0.25, false],
        'components_sha256' => '015fa1bacf0de72854cd5d313a39b3d02bbd2904412e10564b2a34cb868218e9',
        'untrusted' => [],
        'device_key' => '2de4f3945ea2e14bffb52bfdf3b36c7dbda128aeb260b67e35170bc40ec593c3',
    ],
    'demo a browser that contradicts itself' => [
        'disagreements' => ['lied_os:20'],
        'details_sha256' => '7b043be67957207d',
        'reasons' => ['lied_os'],
        'total_weight' => 20,
        'score' => 39,
        'band' => 'pass',
        'confidence' => [18, 2021, 11416],
        'missing' => ['tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => 'da6df9eb41e20c24138f0f44ee953280e2a5424b3d03509516f3803277ab3135',
        'keys' => ['e15e695485ecbeb0e80260101390cdbd764c6dac3efc7651e18afcc0c9edc270', null, 25626, 0.25, false],
        'components_sha256' => '5b4e742e801302462ec1f832c05a7695055fcf6fe9a6c28c2c90668b9c5484c0',
        'untrusted' => [],
        'device_key' => 'e15e695485ecbeb0e80260101390cdbd764c6dac3efc7651e18afcc0c9edc270',
    ],
    'demo a tampered page (integrity probe fired)' => [
        'disagreements' => ['descriptor_patched:30'],
        'details_sha256' => '1272b1e5ff0a91d5',
        'reasons' => ['descriptor_patched'],
        'total_weight' => 30,
        'score' => 53,
        'band' => 'elevated',
        'confidence' => [5, 1100, 11416],
        'missing' => ['tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => ['descriptor_patched:client'],
        'digest' => '07faa455f86d8907a86c47c48246421ae9e61cc2d0aca4fb01272b0892a008da',
        'keys' => ['3ee87cd9ba69ce758093f8f5f76036fc104f186a4e48e56f046eb125ed5f40e1', null, 25626, 0.063, false],
        'components_sha256' => '149dbca75210f8d011160e225705dfca9470dcb52903c71c4147ce3ec61e3634',
        'untrusted' => [],
        'device_key' => '3ee87cd9ba69ce758093f8f5f76036fc104f186a4e48e56f046eb125ed5f40e1',
    ],
    'demo nothing collected (a browser that declined)' => [
        'disagreements' => [],
        'details_sha256' => 'e3b0c44298fc1c14',
        'reasons' => [],
        'total_weight' => 0,
        'score' => 0,
        'band' => 'pass',
        'confidence' => [1, 0, 11416],
        'missing' => ['tier1:environment', 'tier1:dateParsing', 'tier1:codecs', 'tier1:cssMedia', 'tier1:esFeatures', 'tier1:uaClientHints', 'tier1:architecture', 'tier1:engineIdentity', 'tier1:objectShape', 'tier1:removedApiBoundary', 'tier2:textMetrics', 'tier2:audioRealtime', 'tier2:errorText', 'tier2:fontFallback', 'tier2:intl', 'tier2:permissions', 'tier2:audioOffline', 'tier2:heapMemory', 'tier2:workerScope', 'tier2:audioReadback', 'tier2:timezoneLmt', 'tier2:fontFaces', 'tier2:parallelism', 'tier2:gpuMath', 'tier2:buildFingerprint', 'tier2:keyboardLayout', 'tier2:webrtc', 'tier2:behavior', 'tier2:storageProfile', 'tier2:fontMetrics', 'tier2:gpu', 'tier2:audioHardware', 'tier2:scripts', 'tier2:voices', 'tier2:emojiMetrics', 'tier2:decoders'],
        'integrity_codes' => [],
        'digest' => 'a1147f26ab0f00f80524a2619d630cf4f1a0924a3c8013cd509b53e1f896c080',
        'keys' => ['cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347', null, 25626, 0.0, false],
        'components_sha256' => 'f7992319e2c455631ece08b5249e2efebc375188d3edbbb1d02e5f4c8039eade',
        'untrusted' => [],
        'device_key' => 'cb036acca69569b5097155faf6547ea1150a1923a36a1184edb0b014ec196347',
    ],
];

$failures = golden_compare(GOLDEN, $actual);

// Self-check 1: an altered expectation must be reported.
$tampered = GOLDEN;
$firstLabel = array_key_first($tampered);
if ($firstLabel === null) {
    $failures[] = 'no golden values are recorded; run with --record and paste the result';
} else {
    $tampered[$firstLabel]['score'] = -1;
    if (golden_compare($tampered, $actual) === []) {
        $failures[] = 'self-check: an altered expectation was not reported — the comparison is blind';
    }
}

// Self-check 2: the engine must actually feed the comparison. Doubling `lied_os` is not
// enough on its own if no fixture fires it, so EVERY shipped code is set to 1: any fixture
// with a disagreement then changes, and the recorded fixtures include ones that disagree.
$silenced = [];
foreach (array_keys(EnvironmentConsistency::weights()) as $code) {
    $silenced[$code] = 1;
}
if (golden_compare(GOLDEN, golden_run($silenced)) === []) {
    $failures[] = 'self-check: changing every weight changed no pinned answer — the fixtures exercise nothing';
}

$disagreeing = count(array_filter($actual, static fn (array $a): bool => $a['disagreements'] !== []));
$first = reset($actual);
printf("  %d fixture claim sets, %d with disagreements, %d fields pinned each\n", count($actual), $disagreeing, $first === false ? 0 : count($first));

if ($failures !== []) {
    foreach ($failures as $failure) {
        echo "  FAIL  {$failure}\n";
    }
    echo "\nGOLDEN: FAIL\n";
    exit(1);
}

echo "\nGOLDEN: PASS — every fixture produced exactly the recorded answers, and both self-checks can fail\n";
exit(0);

<?php

declare(strict_types=1);

/**
 * The engine step of the capture harness.
 *
 *   php tools/capture/engine-report.php [<capture-dir>] [--save-fixtures=<dir>]
 *
 * Without a directory it reads the newest one under tools/capture/out.
 *
 * Reads <capture-dir>/runs/*.json (written by capture.mjs) and writes next to them:
 *
 *   dataset/<id>.json   one record per run: labels, machine, browser, transport headers, the
 *                       claims of both envelopes, flat `features`, and the engine's reading
 *   dataset/index.jsonl one summary line per run
 *   report.json         everything the report knows
 *   report.md           the human-readable report
 *
 * Exit code 1 when an expectation (`capture-expectations.php`) fails or a run was incomplete.
 */
require __DIR__.'/../../src/autoload.php';
require __DIR__.'/CaptureAnalysis.php';
require __DIR__.'/Expectations.php';

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\Capture\Expectations;

$positional = array_values(array_filter(array_slice($argv, 1), static fn (string $arg): bool => ! str_starts_with($arg, '--')));
$dir = $positional[0] ?? null;
if ($dir === null) {
    // No directory given (`npm run capture:report`): the newest capture under tools/capture/out.
    $latest = glob(__DIR__.'/out/*', GLOB_ONLYDIR) ?: [];
    sort($latest);
    $dir = $latest === [] ? null : end($latest);
}
if ($dir === null || ! is_dir($dir.'/runs')) {
    fwrite(STDERR, "usage: php tools/capture/engine-report.php <capture-dir> [--save-fixtures=<dir>]\n");
    exit(2);
}
$fixtureDir = null;
foreach (array_slice($argv, 2) as $arg) {
    if (str_starts_with($arg, '--save-fixtures=')) {
        $fixtureDir = substr($arg, strlen('--save-fixtures='));
    }
}

CaptureAnalysis::configure();
$rules = Expectations::load();

$files = glob($dir.'/runs/*.json') ?: [];
sort($files);
@mkdir($dir.'/dataset', 0777, true);
if ($fixtureDir !== null) {
    @mkdir($fixtureDir, 0777, true);
}

$records = [];
$results = [];
$failureCount = 0;
$index = [];

foreach ($files as $file) {
    $run = json_decode((string) file_get_contents($file), true, 64, JSON_THROW_ON_ERROR);
    $entry = ['id' => $run['id'], 'failures' => []];

    if (! ($run['complete'] ?? false)) {
        $entry['failures'][] = ['kind' => 'incomplete', 'code' => null, 'message' => 'only the envelopes '.implode(', ', array_map(static fn (array $c): string => $c['slot'], $run['claim_requests'] ?? [])).' arrived; outcome: '.json_encode($run['outcome'])];
        $results[] = $entry;
        $failureCount++;

        continue;
    }

    $record = CaptureAnalysis::toDataset($run);
    $analysis = CaptureAnalysis::analyse($record);
    $failures = Expectations::evaluate($record, $analysis, $rules);
    $failureCount += count($failures);

    $records[] = $record;
    $entry = [
        'id' => $record['id'],
        'class' => $record['labels']['class'],
        'machine' => $record['machine']['id'],
        'os' => $record['machine']['os'],
        'browser' => $record['browser']['name'],
        'version' => $record['browser']['version'],
        'mode' => $record['browser']['mode'],
        'variant' => $record['browser']['variant'],
        'analysis' => $analysis,
        'failures' => $failures,
    ];
    $results[] = $entry;

    $dataset = $record + [
        'features' => CaptureAnalysis::features(CaptureAnalysis::mergedClaims($record)),
        'engine' => [
            'key_secret' => 'capture-harness-fixed-test-secret (not a deployment secret)',
            'verdict' => $analysis['merged'],
            'verdict_tier1_only' => $analysis['tier1'],
            'keys' => $analysis['keys'],
        ],
        'expectations' => ['version' => $rules['version'], 'passed' => $failures === [], 'failures' => $failures],
    ];
    file_put_contents($dir.'/dataset/'.$record['id'].'.json', json_encode($dataset, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
    $index[] = json_encode([
        'id' => $record['id'], 'schema_version' => CaptureAnalysis::DATASET_VERSION, 'label' => $record['labels']['class'],
        'machine' => $record['machine']['id'], 'os' => $record['machine']['os'], 'browser' => $record['browser']['name'],
        'browser_version' => $record['browser']['version'], 'mode' => $record['browser']['mode'],
        'band' => $analysis['merged']['band'], 'score' => $analysis['merged']['score'], 'codes' => array_keys($analysis['merged']['codes']),
        'confidence' => $analysis['merged']['confidence']['score'], 'expectations_passed' => $failures === [],
    ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

    if ($fixtureDir !== null) {
        file_put_contents($fixtureDir.'/'.$record['id'].'.json', json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
    }
}
file_put_contents($dir.'/dataset/index.jsonl', implode("\n", $index).($index === [] ? '' : "\n"));

$pairs = CaptureAnalysis::pairs($records);
$recordsById = [];
foreach ($records as $record) {
    $recordsById[$record['id']] = $record;
}

$harness = is_file($dir.'/harness.json') ? json_decode((string) file_get_contents($dir.'/harness.json'), true) : [];
$skipped = array_values(array_filter($harness['summary'] ?? [], static fn (array $row): bool => ($row['status'] ?? '') !== 'captured' && ($row['status'] ?? '') !== 'incomplete'));

file_put_contents($dir.'/report.json', json_encode([
    'schema' => 'device-id.capture-report', 'schema_version' => 1,
    'machine' => $harness['machine'] ?? null,
    'failure_count' => $failureCount,
    'runs' => $results,
    'pairs' => $pairs,
    'not_run' => $skipped,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");

$md = [];
$md[] = '# Browser capture report';
$md[] = '';
if (isset($harness['machine'])) {
    $m = $harness['machine'];
    $md[] = sprintf('Machine `%s`: %s %s (%s), display: %s, Node %s.', $m['id'], $m['os'], $m['os_release'], $m['arch'], $m['display'], $m['node']);
    $md[] = '';
}
$md[] = sprintf('**%d capture(s), %d expectation failure(s).** Collector envelope v%s, probe set %s.', count($records), $failureCount, $records[0]['collector']['envelope_version'] ?? '?', $records[0]['collector']['probe_set'] ?? '?');
$md[] = '';
$md[] = '## Verdicts (identify form: tier 1 + tier 2)';
$md[] = '';
$md[] = '| Capture | Label | Browser | Mode | Band | Score | Confidence | Codes | Penalties | Expectations |';
$md[] = '|---|---|---|---|---|---|---|---|---|---|';
foreach ($results as $r) {
    if (! isset($r['analysis'])) {
        $md[] = sprintf('| `%s` | | | | | | | | | INCOMPLETE |', $r['id']);

        continue;
    }
    $a = $r['analysis']['merged'];
    $md[] = sprintf(
        '| `%s` | %s | %s %s | %s | %s | %d | %d | %s | %s | %s |',
        $r['id'], $r['class'], $r['browser'], $r['version'], $r['mode'], $a['band'], $a['score'], $a['confidence']['score'],
        implode(', ', array_map(static fn (string $c, array $m): string => $c.':'.$m['weight'], array_keys($a['codes']), $a['codes'])) ?: 'none',
        implode(', ', $a['confidence']['penalties']) ?: 'none',
        $r['failures'] === [] ? 'ok' : 'FAIL ('.count($r['failures']).')',
    );
}
$md[] = '';
$md[] = '## Expectation failures';
$md[] = '';
if ($failureCount === 0) {
    $md[] = 'None.';
} else {
    foreach ($results as $r) {
        foreach ($r['failures'] as $f) {
            $md[] = sprintf('- `%s` [%s]%s %s', $r['id'], $f['kind'], $f['code'] !== null ? ' `'.$f['code'].'`' : '', $f['message']);
        }
    }
}
$md[] = '';
$md[] = '## Same-machine pairs (DeviceMatcher, both directions)';
$md[] = '';
if ($pairs === []) {
    $md[] = 'No pair: fewer than two different browsers captured in one mode on one machine.';
} else {
    $md[] = '| Pair | Direction | Result | Posterior | Veto | Hard key equal | Score | Known reason |';
    $md[] = '|---|---|---|---|---|---|---|---|';
    foreach ($pairs as $p) {
        foreach (['forward' => '->', 'backward' => '<-'] as $key => $arrow) {
            $r = $p[$key];
            $note = $r === null || $r['linked'] ? '' : Expectations::pairNote($p, $r, $recordsById, $rules);
            $md[] = $r === null
                ? sprintf('| `%s` %s `%s` | %s | not keyed | | | | |', $p['a'], '<>', $p['b'], $arrow)
                : sprintf('| `%s` / `%s` | %s | %s | %s | %s | %s | %s |', $p['a'], $p['b'], $arrow, $r['linked'] ? 'LINK' : $r['method'], $r['posterior'], $r['veto'] ?? 'none', $r['hardware_key_equal'] ? 'yes' : 'NO', $r['score'] ?? '-').($note !== '' ? ' '.$note.' |' : ' |');
        }
    }
    $md[] = '';
    $md[] = 'A link is not asserted: signals legitimately differ between browsers. `possible` with veto `none` means no component contradicted the pair.';
}
$md[] = '';
$md[] = '## Not run';
$md[] = '';
foreach ($skipped as $row) {
    $md[] = sprintf('- `%s`: %s (%s)', $row['id'], $row['status'], $row['reason'] ?? '');
}
if ($skipped === []) {
    $md[] = 'Everything requested ran.';
}
$md[] = '';
file_put_contents($dir.'/report.md', implode("\n", $md));

echo implode("\n", $md)."\n";
echo "\nReport: {$dir}/report.md, {$dir}/report.json; dataset: {$dir}/dataset/\n";
echo $failureCount === 0 ? "EXPECTATIONS: all met\n" : "EXPECTATIONS: {$failureCount} failure(s)\n";
exit($failureCount === 0 ? 0 : 1);

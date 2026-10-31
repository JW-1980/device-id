<?php

declare(strict_types=1);

/**
 * The engine step of the red-team harness.
 *
 *   php tools/redteam/report.php <redteam-dir> [--save-fixtures=<dir>]
 *
 * Reads <dir>/runs/*.json (written by run.mjs) and writes next to them dataset/<id>.json (the
 * capture dataset format, class `spoof` with `labels.name = spoof:<tool>`), report.json and
 * report.md: per tool and mode the band, score, codes, confidence, whether it is flagged
 * (band challenge or block), whether the device key is fresh per run, and whether the matcher
 * links it to the honest baseline of the same machine and mode.
 *
 * Exit code 1 when a tool was not flagged (so a regression is visible in CI-style use).
 */
require __DIR__.'/../../src/autoload.php';
require __DIR__.'/../capture/CaptureAnalysis.php';

use DeviceId\Capture\CaptureAnalysis;

$positional = array_values(array_filter(array_slice($argv, 1), static fn (string $a): bool => ! str_starts_with($a, '--')));
$dir = $positional[0] ?? null;
if ($dir === null || ! is_dir($dir.'/runs')) {
    fwrite(STDERR, "usage: php tools/redteam/report.php <redteam-dir> [--save-fixtures=<dir>]\n");
    exit(2);
}
$fixtureDir = null;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--save-fixtures=')) {
        $fixtureDir = substr($arg, strlen('--save-fixtures='));
    }
}

CaptureAnalysis::configure();
$files = glob($dir.'/runs/*.json') ?: [];
sort($files);
@mkdir($dir.'/dataset', 0777, true);
if ($fixtureDir !== null) {
    @mkdir($fixtureDir, 0777, true);
}

$rows = [];
$baselines = [];
$index = [];
foreach ($files as $file) {
    $run = json_decode((string) file_get_contents($file), true, 64, JSON_THROW_ON_ERROR);
    if (! ($run['complete'] ?? false)) {
        continue;
    }
    $record = CaptureAnalysis::toDataset($run);
    $analysis = CaptureAnalysis::analyse($record);
    $merged = $analysis['merged'];
    $row = [
        'id' => $record['id'],
        'tool' => $record['labels']['tool'],
        'class' => $record['labels']['class'],
        'repeat' => $record['labels']['repeat'] ?? 1,
        'mode' => str_starts_with($record['browser']['mode'], 'headless') ? 'headless' : 'headed',
        'driver' => $record['browser']['driver'],
        'version' => $record['browser']['version'],
        'band' => $merged['band'],
        'score' => $merged['score'],
        'codes' => $merged['codes'],
        'integrity_codes' => $merged['integrity_codes'],
        'confidence' => $merged['confidence']['score'],
        'penalties' => $merged['confidence']['penalties'],
        'flagged' => in_array($merged['band'], ['challenge', 'block'], true),
        'browser_key' => $analysis['keys']['browser_key'] ?? null,
        'hardware_key' => $analysis['keys']['hardware_key'] ?? null,
        'record' => $record,
    ];
    if ($record['labels']['name'] === 'honest:baseline') {
        $baselines[$row['mode']] = $record;
    }
    $rows[] = $row;

    file_put_contents($dir.'/dataset/'.$record['id'].'.json', json_encode($record + [
        'features' => CaptureAnalysis::features(CaptureAnalysis::mergedClaims($record)),
        'engine' => ['key_secret' => 'capture-harness-fixed-test-secret (not a deployment secret)', 'verdict' => $merged, 'verdict_tier1_only' => $analysis['tier1'], 'keys' => $analysis['keys']],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
    $index[] = json_encode(['id' => $record['id'], 'label' => $record['labels']['class'], 'name' => $record['labels']['name'], 'mode' => $row['mode'], 'band' => $row['band'], 'score' => $row['score'], 'codes' => array_keys($row['codes']), 'confidence' => $row['confidence']], JSON_UNESCAPED_SLASHES);
    if ($fixtureDir !== null && $row['repeat'] === 1) {
        file_put_contents($fixtureDir.'/'.$record['id'].'.json', json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
    }
}
file_put_contents($dir.'/dataset/index.jsonl', implode("\n", $index).($index === [] ? '' : "\n"));

/** Per tool and mode: the first run's verdict, key freshness over the repeats, matcher link to the baseline. */
$tools = [];
foreach ($rows as $row) {
    $tools[$row['tool']][$row['mode']][] = $row;
}
$summary = [];
foreach ($tools as $tool => $modes) {
    foreach ($modes as $mode => $runs) {
        $first = $runs[0];
        $keys = array_values(array_unique(array_map(static fn (array $r): string => (string) $r['browser_key'], $runs)));
        $hardware = array_values(array_unique(array_map(static fn (array $r): string => (string) $r['hardware_key'], $runs)));
        $baseline = $baselines[$mode] ?? null;
        $match = $baseline !== null && $first['tool'] !== 'baseline' ? CaptureAnalysis::match($baseline, $first['record']) : null;
        $summary[] = [
            'tool' => $tool, 'mode' => $mode, 'class' => $first['tool'] === 'baseline' ? 'baseline' : 'spoof', 'driver' => $first['driver'], 'version' => $first['version'],
            'runs' => count($runs),
            'band' => $first['band'], 'score' => $first['score'], 'confidence' => $first['confidence'], 'flagged' => $first['flagged'],
            'codes' => array_map(static fn (string $c, array $m): string => $c.':'.$m['weight'], array_keys($first['codes']), $first['codes']),
            'all_runs_flagged' => ! in_array(false, array_column($runs, 'flagged'), true),
            'browser_keys_distinct' => count($keys),
            'fresh_identity_per_run' => count($runs) > 1 ? count($keys) === count($runs) : null,
            'hardware_key_stable' => count($hardware) === 1,
            'links_to_honest_baseline' => $match === null ? null : $match['linked'],
            'match' => $match === null ? null : ['method' => $match['method'], 'posterior' => $match['posterior'], 'veto' => $match['veto'], 'hardware_key_equal' => $match['hardware_key_equal']],
        ];
    }
}
$harness = is_file($dir.'/harness.json') ? json_decode((string) file_get_contents($dir.'/harness.json'), true) : [];
$notRun = array_values(array_filter($harness['summary'] ?? [], static fn (array $r): bool => ! in_array($r['status'] ?? '', ['captured'], true)));
$unflagged = array_values(array_filter($summary, static fn (array $s): bool => $s['class'] === 'spoof' && ! $s['all_runs_flagged']));

file_put_contents($dir.'/report.json', json_encode(['schema' => 'device-id.redteam-report', 'schema_version' => 1, 'machine' => $harness['machine'] ?? null, 'tools' => $summary, 'not_run' => $notRun], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");

$md = ['# Red-team report', ''];
$md[] = '| Tool | Mode | Band | Score | Conf. | Flagged | Fresh id per run | Links to honest | Codes |';
$md[] = '|---|---|---|---|---|---|---|---|---|';
$yn = static fn (?bool $v): string => $v === null ? 'n/a' : ($v ? 'yes' : 'no');
foreach ($summary as $s) {
    $md[] = sprintf('| %s | %s | %s | %d | %d | %s | %s | %s | %s |', $s['tool'], $s['mode'], $s['band'], $s['score'], $s['confidence'], $s['class'] === 'baseline' ? '(baseline)' : $yn($s['all_runs_flagged']), $yn($s['fresh_identity_per_run']), $yn($s['links_to_honest_baseline']), implode(', ', $s['codes']) ?: 'none');
}
$md[] = '';
$md[] = '"Flagged" means band challenge or block on every repeat. "Fresh id per run": the browser key differs between repeats. "Links to honest": DeviceMatcher links the first run to the plainly driven Chromium of the same machine and mode.';
$md[] = '';
$md[] = '## Not run';
foreach ($notRun as $r) {
    $md[] = sprintf('- `%s`: %s %s', $r['id'], $r['status'], $r['reason'] ?? '');
}
if ($notRun === []) {
    $md[] = 'Everything requested ran.';
}
$md[] = '';
file_put_contents($dir.'/report.md', implode("\n", $md));
echo implode("\n", $md)."\n";
if ($unflagged !== []) {
    echo 'NOT FLAGGED: '.implode(', ', array_map(static fn (array $s): string => $s['tool'].'/'.$s['mode'], $unflagged))."\n";
}
exit($unflagged === [] ? 0 : 1);

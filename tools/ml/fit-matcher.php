<?php

declare(strict_types=1);

/**
 * Fits Fellegi-Sunter matcher weights from host-exported pair comparisons and writes the
 * weights file the matcher loads in shadow mode.
 *
 *   php tools/ml/fit-matcher.php --pairs=pairs.jsonl [--out=matcher-weights.json] [--iterations=100]
 *
 * pairs.jsonl: one JSON object per line, built by the host from `LearnedMatcher::comparisons()`:
 *   {"c": {"fonts": true, "gpu": true, "panel": false, "browser_key": true},
 *    "slice": "chromium:desktop", "same": true}
 * `same` is true / false when the host knows (same account and cookie = same device), null
 * when it does not (the pair is then estimated). Components that said nothing are omitted.
 *
 * Refuses (exit 1) when either class has fewer than 5 effective pairs. The weights are for
 * `shadow` until every slice has 1,000 pairs (`LearnedWeights::promotion()`); the report says
 * which slices are short.
 */
require __DIR__.'/../../src/autoload.php';

use DeviceId\Matching\FellegiSunter;

$options = [];
foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $arg, $m) === 1) {
        $options[$m[1]] = $m[2] ?? 'true';
    }
}
if (! isset($options['pairs']) || ! is_file($options['pairs'])) {
    fwrite(STDERR, "usage: php tools/ml/fit-matcher.php --pairs=pairs.jsonl [--out=file]\n");
    exit(2);
}

$pairs = [];
$hash = hash_init('sha256');
foreach (file($options['pairs'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    hash_update($hash, $line."\n");
    $row = json_decode($line, true);
    if (is_array($row) && is_array($row['c'] ?? null)) {
        $pairs[] = ['c' => array_map(static fn (mixed $v): bool => $v === true, $row['c']), 'slice' => (string) ($row['slice'] ?? 'all'), 'same' => array_key_exists('same', $row) && is_bool($row['same']) ? $row['same'] : null];
    }
}

$weights = FellegiSunter::estimate($pairs, null, (int) ($options['iterations'] ?? 100), 0.5, ['pairs_sha256' => hash_final($hash), 'fitted_at' => gmdate('c')]);
if ($weights === null) {
    fwrite(STDERR, "not enough pairs of each class to estimate m and u (need at least 5 effective pairs of same and of different devices)\n");
    exit(1);
}

$out = $options['out'] ?? 'matcher-weights.json';
file_put_contents($out, json_encode($weights->toArray(), JSON_PRETTY_PRINT | JSON_PRESERVE_ZERO_FRACTION)."\n");

echo "wrote {$out}\n";
$promotion = $weights->promotion();
echo $promotion['promotable'] ? "promotable: every slice has at least {$promotion['minimum']} pairs\n" : 'SHADOW ONLY, short slices: '.json_encode($promotion['short_slices'])."\n";
printf("%-14s %8s %8s   %s\n", 'component', 'agree', 'disagree', 'm_agree / u_agree');
foreach ($weights->weights as $name => $w) {
    printf("%-14s %8.2f %8.2f   %.3f / %.3f\n", $name, $w['agree'], $w['disagree'], $w['m_agree'], $w['u_agree']);
}

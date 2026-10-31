<?php

declare(strict_types=1);

/**
 * Trains the verdict model in pure PHP and writes a sealed, versioned model JSON.
 *
 *   php tools/ml/train.php [--dataset=dir[,dir]] [--rows=export.jsonl] [--out=model.json]
 *                          [--report=report.md] [--lambda=1.0] [--seed=device-id]
 *                          [--validation=0.3] [--assumed-prevalence=0.02]
 *                          [--max-adjustment=20] [--retention-days=365] [--bootstrap=40]
 *
 * Inputs (either or both):
 *   --dataset  capture-harness dataset records (default tests/Fixtures/ml/dataset and tests/Fixtures/fingerprint/redteam)
 *   --rows     a JSONL export of de-identified training rows (`TrainingRowBuilder`), one per line:
 *              this is how a host's own traffic reaches the trainer. No Python, no network.
 *
 * It runs wherever PHP 8.2 runs, on the owner's own server, in seconds for tens of thousands of
 * rows. The model is only a proposal until the owner points `fingerprint.model.path` at it and
 * chooses a mode; promotion criteria are in the README.
 */
require __DIR__.'/../../src/autoload.php';
require __DIR__.'/CaptureRows.php';
require __DIR__.'/Report.php';

use DeviceId\Ml\CaptureRows;
use DeviceId\Ml\Report;
use DeviceId\Model\ModelBuilder;
use DeviceId\Model\ModelSpec;
use DeviceId\Model\TrainingRow;
use DeviceId\Model\WeightProposal;

$options = [];
foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $arg, $m) === 1) {
        $options[$m[1]] = $m[2] ?? 'true';
    }
}

$directories = explode(',', $options['dataset'] ?? (isset($options['rows']) ? '' : __DIR__.'/../../tests/Fixtures/ml/dataset,'.__DIR__.'/../../tests/Fixtures/fingerprint/redteam'));
$directories = array_values(array_filter($directories, static fn (string $d): bool => $d !== ''));
$loaded = $directories === [] ? ['rows' => [], 'files' => [], 'sha256' => hash('sha256', '')] : CaptureRows::load($directories);
$rows = $loaded['rows'];
$hash = hash_init('sha256');
hash_update($hash, $loaded['sha256']);

if (isset($options['rows'])) {
    $lines = file($options['rows'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    foreach ($lines as $line) {
        hash_update($hash, $line."\n");
        $row = TrainingRow::fromArray(json_decode($line, true) ?: []);
        if ($row !== null) {
            $rows[] = $row;
        }
    }
}
if ($rows === []) {
    fwrite(STDERR, "no training rows found\n");
    exit(2);
}

$machines = [];
foreach ($rows as $row) {
    $machines[explode('|', $row->group)[0]] = true;
}
$trainedAt = isset($options['trained-at']) ? (int) strtotime($options['trained-at']) : time();

$build = ModelBuilder::build($rows, [
    'lambda' => (float) ($options['lambda'] ?? 1.0),
    'seed' => $options['seed'] ?? 'device-id',
    'validation_fraction' => (float) ($options['validation'] ?? 0.3),
    'training_set_sha256' => hash_final($hash),
    'trained_at' => $trainedAt,
    'retention_days' => (int) ($options['retention-days'] ?? 365),
    'assumed_prevalence' => isset($options['assumed-prevalence']) ? (float) $options['assumed-prevalence'] : null,
    'max_adjustment_weight' => (int) ($options['max-adjustment'] ?? 20),
    'split_unit' => count($machines) >= 3 ? 'machine' : 'machine|browser|mode|recipe (fewer than 3 machines)',
]);
$document = $build['document'];

$check = ModelSpec::fromArray($document, 45, $trainedAt);
if ($check['state'] !== ModelSpec::STATE_OK) {
    fwrite(STDERR, 'the trained model does not load: '.$check['state'].' '.$check['reason']."\n");
    exit(1);
}

$out = $options['out'] ?? __DIR__.'/out/model.json';
@mkdir(dirname($out), 0777, true);
file_put_contents($out, json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION)."\n");

$fit = ['features' => $document['features'], 'coefficients' => $document['coefficients']];
$proposal = WeightProposal::build($rows, $fit, (float) ($options['lambda'] ?? 1.0), (int) ($options['bootstrap'] ?? 40), $options['seed'] ?? 'device-id');

$report = Report::training($document, $build['report'], $proposal, count($rows));
$reportPath = $options['report'] ?? preg_replace('/\.json$/', '', $out).'.report.md';
file_put_contents($reportPath, $report);

echo "model:    {$out}\nreport:   {$reportPath}\nid:       {$document['model_id']}\nrows:     ".count($rows)." (train {$document['split']['train_rows']}, validation {$document['split']['validation_rows']})\nsha256:   {$document['sha256']}\n";

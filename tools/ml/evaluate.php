<?php

declare(strict_types=1);

/**
 * Offline evaluation: rules alone and, with --model, a trained model, on the same rows,
 * overall and per slice (engine, mobile/desktop, privacy mode, label class), with precision and
 * recall at fixed false-positive rates and calibration (ECE).
 *
 *   php tools/ml/evaluate.php [--dataset=dir[,dir]] [--model=model.json] [--all]
 *                             [--out=report.md] [--json=report.json] [--fail-on-slice-regression]
 *
 * With --model the model is judged on its own held-out groups (the validation groups recorded
 * in the model file), because judging it on rows it trained on measures memory. --all overrides
 * that and says so in the report. Exit code 1 with --fail-on-slice-regression when the model's
 * false-positive rate exceeds the rules' on any slice that has honest rows (the CI guard from
 * the design: a candidate that harms one browser class cannot be promoted).
 *
 * It needs no network and no dependency: it runs offline.
 */
require __DIR__.'/../../src/autoload.php';
require __DIR__.'/CaptureRows.php';
require __DIR__.'/Report.php';

use DeviceId\Ml\CaptureRows;
use DeviceId\Ml\Report;
use DeviceId\Model\Evaluator;
use DeviceId\Model\ModelSpec;
use DeviceId\Model\TrainingRow;

$options = [];
foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $arg, $m) === 1) {
        $options[$m[1]] = $m[2] ?? 'true';
    }
}

$loaded = CaptureRows::load(explode(',', $options['dataset'] ?? __DIR__.'/../../tests/Fixtures/ml/dataset,'.__DIR__.'/../../tests/Fixtures/fingerprint/redteam'));
$rows = $loaded['rows'];
$note = 'rows: '.count($rows).'; dataset sha256 `'.$loaded['sha256'].'`. Labels are harness-declared (see `basis` in each record); the honest class is scripted browsers, not people.';

$probability = null;
$rulesCalibration = null;
if (isset($options['model'])) {
    $load = ModelSpec::load($options['model'], PHP_INT_MAX >> 8);
    if ($load['model'] === null) {
        fwrite(STDERR, 'model not usable: '.$load['state'].' '.$load['reason']."\n");
        exit(2);
    }
    $model = $load['model'];
    $probability = static fn (TrainingRow $row): float => $model->predict($row->features)->probability;
    $rulesCalibration = $model->rulesCalibration;
    if (! isset($options['all'])) {
        $validation = array_flip($model->document['split']['validation_groups'] ?? []);
        $rows = array_values(array_filter($rows, static fn (TrainingRow $row): bool => isset($validation[$row->group])));
        $note .= ' Evaluated on the model\'s held-out groups only ('.count($rows).' rows); the rules are scored on the same rows.';
    } else {
        $note .= ' ALL rows, including rows the model trained on: the model figures are in-sample.';
    }
}

$slices = Evaluator::evaluate($rows, $probability, $rulesCalibration);
$markdown = Report::evaluation('Evaluation report', $slices, $note);
echo $markdown;

if (isset($options['out'])) {
    file_put_contents($options['out'], $markdown);
}
if (isset($options['json'])) {
    file_put_contents($options['json'], json_encode(['note' => $note, 'slices' => $slices], JSON_PRETTY_PRINT | JSON_PRESERVE_ZERO_FRACTION)."\n");
}

if (isset($options['fail-on-slice-regression']) && $probability !== null) {
    $bad = [];
    foreach ($slices as $name => $slice) {
        $rules = $slice['rules']['false_positive_rate_at_flag'];
        $model = $slice['model']['false_positive_rate_at_flag'] ?? null;
        if ($rules !== null && $model !== null && $model > $rules) {
            $bad[] = "{$name}: model FPR {$model} > rules FPR {$rules}";
        }
    }
    if ($bad !== []) {
        fwrite(STDERR, "\nSLICE REGRESSION:\n".implode("\n", $bad)."\n");
        exit(1);
    }
}

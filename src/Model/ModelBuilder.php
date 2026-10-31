<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * Trains a model document from de-identified rows: split by linked unit into train,
 * calibration and validation ({@see Splitter::threeWay()}), fit on train, calibrate on
 * calibration, measure on validation, seal. Validation rows neither trained nor calibrated
 * the model, so the promotion metrics (FPR, ECE) are out of sample (skeptical review M8:
 * calibration used to be fitted on the very rows it was then judged on). This is what `tools/ml/train.php` runs, and it is pure PHP so
 * it can run on the owner's own server.
 *
 * ## Calibration prior
 *
 * The probabilities are calibrated to the prevalence of the TRAINING SET, which for harness
 * data is nothing like production (half the rows are bots). `assumed_prevalence` moves the
 * calibration intercept to a stated production prior; without it the document records
 * `calibrated_to: "training_prevalence"` so nobody reads `p = 0.9` as a 90 % chance in real
 * traffic. In `bounded` mode only the DIFFERENCE between the model's and the rules' log-odds
 * is used, and both are calibrated on the same rows, so the prior cancels.
 */
final class ModelBuilder
{
    public const TRAINER = 'device-id-php';

    public const TRAINER_VERSION = '1';

    /**
     * @param  list<TrainingRow>  $rows
     * @param  array{lambda?: float, validation_fraction?: float, calibration_fraction?: float, seed?: string, max_coefficient?: float, trained_at?: int, training_set_sha256?: string, retention_days?: int, assumed_prevalence?: float|null, max_adjustment_weight?: int, min_rule_families?: int, model_id?: string, score_divisor?: int, split_unit?: string}  $options
     * @return array{document: array<string, mixed>, report: array<string, mixed>}
     */
    public static function build(array $rows, array $options = []): array
    {
        if (count($rows) < 4 || count(array_filter($rows, static fn (TrainingRow $r): bool => $r->isPositive())) === 0 || count(array_filter($rows, static fn (TrainingRow $r): bool => ! $r->isPositive())) === 0) {
            throw new \InvalidArgumentException('training needs both honest and non-honest rows (at least 4 in all)');
        }

        $lambda = $options['lambda'] ?? 1.0;
        $seed = $options['seed'] ?? 'device-id';
        $split = Splitter::threeWay($rows, $options['calibration_fraction'] ?? 0.25, $options['validation_fraction'] ?? 0.25, $seed);
        $fit = LogisticTrainer::fit($split['train'], $lambda, null, $options['max_coefficient'] ?? 6.0);

        $identity = ['a' => 1.0, 'b' => 0.0];
        $raw = self::modelOf($fit, $identity, null, $options);
        $calibrationItems = array_map(static fn (TrainingRow $r): array => ['score' => $raw->predict($r->features)->logit, 'positive' => $r->isPositive(), 'weight' => $r->labelWeight], $split['calibration']);
        $platt = Platt::fit($calibrationItems);

        $assumed = $options['assumed_prevalence'] ?? null;
        $calibratedTo = 'training_prevalence';
        if ($assumed !== null && $assumed > 0.0 && $assumed < 1.0) {
            $positives = array_sum(array_map(static fn (TrainingRow $r): float => $r->isPositive() ? $r->labelWeight : 0.0, $split['calibration']));
            $all = array_sum(array_map(static fn (TrainingRow $r): float => $r->labelWeight, $split['calibration']));
            $observed = max(1e-6, min(1 - 1e-6, $positives / max(1e-9, $all)));
            $platt['b'] += LogisticModel::logit($assumed) - LogisticModel::logit($observed);
            $calibratedTo = 'assumed_prevalence:'.$assumed;
        }

        $rulesItems = array_map(static fn (TrainingRow $r): array => ['score' => (float) $r->rulesWeight, 'positive' => $r->isPositive(), 'weight' => $r->labelWeight], $split['calibration']);
        $rulesPlatt = Platt::fit($rulesItems);
        $rulesFittedOn = 'calibration';
        if (! $rulesPlatt['fitted']) {
            // Too few calibration rows: fall back to train + calibration, never to validation.
            $rulesPlatt = Platt::fit(array_map(static fn (TrainingRow $r): array => ['score' => (float) $r->rulesWeight, 'positive' => $r->isPositive(), 'weight' => $r->labelWeight], [...$split['train'], ...$split['calibration']]));
            $rulesFittedOn = 'train+calibration';
        }
        $rulesCalibration = $rulesPlatt['fitted'] ? ['a' => $rulesPlatt['a'], 'b' => $rulesPlatt['b']] : null;

        $model = self::modelOf($fit, ['a' => $platt['a'], 'b' => $platt['b']], $rulesCalibration, $options);
        $divisor = $options['score_divisor'] ?? 40;
        $heldOut = Evaluator::evaluate($split['validation'], static fn (TrainingRow $r): float => $model->predict($r->features)->probability, $rulesCalibration, $divisor);
        $calibration = Evaluator::evaluate($split['calibration'], static fn (TrainingRow $r): float => $model->predict($r->features)->probability, $rulesCalibration, $divisor);
        $training = Evaluator::evaluate($split['train'], static fn (TrainingRow $r): float => $model->predict($r->features)->probability, $rulesCalibration, $divisor);

        $trainedAt = $options['trained_at'] ?? time();
        $id = $options['model_id'] ?? 'verdict-logit-'.gmdate('Y-m-d', $trainedAt).'-'.substr(hash('sha256', json_encode([$fit['features'], $fit['coefficients'], $fit['intercept']], JSON_THROW_ON_ERROR)), 0, 6);

        $document = ModelSpec::seal([
            'schema' => ModelSpec::SCHEMA,
            'model_id' => $id,
            'kind' => 'logistic',
            'task' => 'verdict',
            'trained_at' => gmdate('Y-m-d\TH:i:s\Z', $trainedAt),
            'training_set_sha256' => $options['training_set_sha256'] ?? '',
            'trainer' => ['lib' => self::TRAINER, 'version' => self::TRAINER_VERSION, 'lambda' => $lambda, 'seed' => $seed],
            'features' => $fit['features'],
            'intercept' => $fit['intercept'],
            'coefficients' => $fit['coefficients'],
            'calibration' => ['method' => 'platt', 'a' => $platt['a'], 'b' => $platt['b'], 'fitted' => $platt['fitted'], 'calibrated_to' => $calibratedTo, 'fitted_on' => $platt['fitted'] ? 'calibration' : 'none (identity: calibration split too small)', 'rules_fitted_on' => $rulesPlatt['fitted'] ? $rulesFittedOn : 'none'],
            'rules_calibration' => $rulesCalibration,
            'bounds' => ['max_adjustment_weight' => $options['max_adjustment_weight'] ?? 20, 'min_rule_families_for_escalation' => $options['min_rule_families'] ?? 2],
            'retention' => ['training_row_days' => $options['retention_days'] ?? 365],
            'split' => [
                'unit' => ($options['split_unit'] ?? 'group').', linked by account (union of device and account linkage)',
                'train_rows' => count($split['train']), 'calibration_rows' => count($split['calibration']), 'validation_rows' => count($split['validation']),
                'train_groups' => $split['groups']['train'], 'calibration_groups' => $split['groups']['calibration'], 'validation_groups' => $split['groups']['validation'],
            ],
            'training' => ['frozen_at_zero' => $fit['frozen'], 'clipped' => $fit['clipped'], 'iterations' => $fit['iterations'], 'converged' => $fit['converged']],
            'metrics' => ['validation' => $heldOut['all'], 'validation_slices' => $heldOut, 'calibration' => $calibration['all'], 'training' => $training['all']],
        ]);

        return ['document' => $document, 'report' => ['held_out' => $heldOut, 'calibration' => $calibration, 'training' => $training, 'split' => $split['groups']]];
    }

    /**
     * @param  array{features: list<string>, coefficients: list<float>, intercept: float}  $fit
     * @param  array{a: float, b: float}  $calibration
     * @param  array{a: float, b: float}|null  $rulesCalibration
     * @param  array<string, mixed>  $options
     */
    private static function modelOf(array $fit, array $calibration, ?array $rulesCalibration, array $options): LogisticModel
    {
        return new LogisticModel('candidate', $fit['features'], $fit['coefficients'], $fit['intercept'], $calibration, $rulesCalibration, $options['max_adjustment_weight'] ?? 20, $options['min_rule_families'] ?? 2, null, []);
    }
}

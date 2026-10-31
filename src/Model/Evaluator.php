<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * The offline evaluation: rules alone and a model, on the same rows, overall and per slice.
 *
 * The rules' score is the same curve the engine uses (`100 * (1 - exp(-weight / divisor))`),
 * so "rules alone" is the shipped behaviour and not a re-implementation of it. Every slice
 * reports its own counts: a slice with no honest rows has no false-positive rate, and says so
 * (`null`) instead of pretending zero.
 */
final class Evaluator
{
    public const FPR_TARGETS = [0.01, 0.005, 0.001];

    /** The score at which a rules verdict is a `challenge` (the shipped band). */
    public const CHALLENGE_SCORE = 60;

    /**
     * @param  list<TrainingRow>  $rows
     * @param  (callable(TrainingRow): float)|null  $modelProbability  null evaluates the rules only
     * @param  array{a: float, b: float}|null  $rulesCalibration  turns the rules' weight into a probability for ECE
     * @return array<string, mixed>
     */
    public static function evaluate(array $rows, ?callable $modelProbability = null, ?array $rulesCalibration = null, int $divisor = 40): array
    {
        $slices = ['all' => $rows];
        foreach ($rows as $row) {
            $slices['engine:'.$row->slice['engine']][] = $row;
            $slices['device:'.$row->slice['device']][] = $row;
            $slices['privacy:'.$row->slice['privacy']][] = $row;
            $slices['class:'.$row->label][] = $row;
        }
        ksort($slices);

        $report = [];
        foreach ($slices as $name => $subset) {
            $report[$name] = self::slice($subset, $modelProbability, $rulesCalibration, $divisor);
        }

        return $report;
    }

    /**
     * @param  list<TrainingRow>  $rows
     * @return array<string, mixed>
     */
    private static function slice(array $rows, ?callable $modelProbability, ?array $rulesCalibration, int $divisor): array
    {
        $positives = count(array_filter($rows, static fn (TrainingRow $r): bool => $r->isPositive()));
        $rulesScores = array_map(static fn (TrainingRow $r): array => ['score' => 100.0 * (1.0 - exp(-$r->rulesWeight / max(1, $divisor))), 'positive' => $r->isPositive()], $rows);

        $out = ['n' => count($rows), 'positives' => $positives, 'negatives' => count($rows) - $positives, 'rules' => self::summary($rulesScores, self::CHALLENGE_SCORE, false)];

        if ($rulesCalibration !== null) {
            $out['rules']['ece'] = Metrics::ece(array_map(static fn (TrainingRow $r): array => [
                'score' => LogisticModel::sigmoid($rulesCalibration['a'] * $r->rulesWeight + $rulesCalibration['b']), 'positive' => $r->isPositive(),
            ], $rows))['ece'];
        }

        if ($modelProbability !== null) {
            $scores = array_map(static fn (TrainingRow $r): array => ['score' => $modelProbability($r), 'positive' => $r->isPositive()], $rows);
            $out['model'] = self::summary($scores, 0.5, true);
        }

        return $out;
    }

    /**
     * @param  list<array{score: float, positive: bool}>  $items
     * @return array<string, mixed>
     */
    private static function summary(array $items, float $flagAt, bool $withEce): array
    {
        $flagged = array_filter($items, static fn (array $i): bool => $i['score'] >= $flagAt);
        $positives = array_filter($items, static fn (array $i): bool => $i['positive']);
        $negatives = array_filter($items, static fn (array $i): bool => ! $i['positive']);
        $summary = [
            'auc' => Metrics::auc($items),
            'flag_threshold' => $flagAt,
            'recall_at_flag' => $positives === [] ? null : round(count(array_filter($positives, static fn (array $i): bool => $i['score'] >= $flagAt)) / count($positives), 4),
            'false_positive_rate_at_flag' => $negatives === [] ? null : round(count(array_filter($negatives, static fn (array $i): bool => $i['score'] >= $flagAt)) / count($negatives), 4),
            'flagged' => count($flagged),
            'at_fpr' => array_map(static fn (float $fpr): array => Metrics::atFalsePositiveRate($items, $fpr), self::FPR_TARGETS),
        ];
        if ($withEce) {
            $summary['ece'] = Metrics::ece($items)['ece'];
            $summary['reliability'] = Metrics::ece($items)['bins'];
        }

        return $summary;
    }
}

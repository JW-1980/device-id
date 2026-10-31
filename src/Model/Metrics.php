<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * Evaluation arithmetic: AUC, expected calibration error, and precision/recall at a fixed
 * false-positive rate. Pure functions over `list<array{score: float, positive: bool}>`.
 */
final class Metrics
{
    /**
     * Area under the ROC curve (Mann-Whitney, ties count half), or null with a single class.
     *
     * @param  list<array{score: float, positive: bool}>  $items
     */
    public static function auc(array $items): ?float
    {
        $positives = array_values(array_filter($items, static fn (array $i): bool => $i['positive']));
        $negatives = array_values(array_filter($items, static fn (array $i): bool => ! $i['positive']));
        if ($positives === [] || $negatives === []) {
            return null;
        }
        $wins = 0.0;
        foreach ($positives as $p) {
            foreach ($negatives as $n) {
                $wins += $p['score'] > $n['score'] ? 1.0 : ($p['score'] === $n['score'] ? 0.5 : 0.0);
            }
        }

        return round($wins / (count($positives) * count($negatives)), 6);
    }

    /**
     * Expected calibration error over equal-width bins of a probability.
     *
     * @param  list<array{score: float, positive: bool}>  $items  score is a probability
     * @return array{ece: float|null, bins: list<array{lo: float, hi: float, n: int, mean_p: float, observed: float}>}
     */
    public static function ece(array $items, int $bins = 10): array
    {
        if ($items === []) {
            return ['ece' => null, 'bins' => []];
        }
        $buckets = array_fill(0, $bins, ['n' => 0, 'sum' => 0.0, 'pos' => 0]);
        foreach ($items as $item) {
            $index = min($bins - 1, (int) floor(max(0.0, min(1.0, $item['score'])) * $bins));
            $buckets[$index]['n']++;
            $buckets[$index]['sum'] += $item['score'];
            $buckets[$index]['pos'] += $item['positive'] ? 1 : 0;
        }
        $total = count($items);
        $ece = 0.0;
        $out = [];
        foreach ($buckets as $index => $bucket) {
            if ($bucket['n'] === 0) {
                continue;
            }
            $mean = $bucket['sum'] / $bucket['n'];
            $observed = $bucket['pos'] / $bucket['n'];
            $ece += $bucket['n'] / $total * abs($mean - $observed);
            $out[] = ['lo' => $index / $bins, 'hi' => ($index + 1) / $bins, 'n' => $bucket['n'], 'mean_p' => round($mean, 4), 'observed' => round($observed, 4)];
        }

        return ['ece' => round($ece, 6), 'bins' => $out];
    }

    /**
     * Recall and precision at the loosest threshold whose false-positive rate on the negatives
     * does not exceed `$fpr`. With `n` negatives the smallest non-zero rate is `1/n`: when
     * `$fpr < 1/n` the only threshold with FPR below target flags nothing and the point is
     * reported with `resolution_limited`, never as a measured zero-FPR recall.
     *
     * @param  list<array{score: float, positive: bool}>  $items
     * @return array{fpr_target: float, threshold: float|null, recall: float|null, precision: float|null, fpr: float|null, negatives: int, positives: int, resolution_limited: bool}
     */
    public static function atFalsePositiveRate(array $items, float $fpr): array
    {
        $positives = array_values(array_filter($items, static fn (array $i): bool => $i['positive']));
        $negatives = array_values(array_filter($items, static fn (array $i): bool => ! $i['positive']));
        $result = ['fpr_target' => $fpr, 'threshold' => null, 'recall' => null, 'precision' => null, 'fpr' => null, 'negatives' => count($negatives), 'positives' => count($positives), 'resolution_limited' => false];
        if ($positives === [] || $negatives === []) {
            return $result;
        }

        $allowed = (int) floor($fpr * count($negatives) + 1e-9);
        $result['resolution_limited'] = $allowed === 0 && $fpr > 0.0;

        $negScores = array_column($negatives, 'score');
        rsort($negScores);
        // Flag a visitor when score is STRICTLY above the threshold, the (allowed+1)-th highest negative.
        $threshold = $negScores[$allowed] ?? -INF;
        $flaggedPositives = count(array_filter($positives, static fn (array $i): bool => $i['score'] > $threshold));
        $flaggedNegatives = count(array_filter($negatives, static fn (array $i): bool => $i['score'] > $threshold));

        $result['threshold'] = is_infinite($threshold) ? null : round($threshold, 6);
        $result['recall'] = round($flaggedPositives / count($positives), 4);
        $result['fpr'] = round($flaggedNegatives / count($negatives), 4);
        $result['precision'] = $flaggedPositives + $flaggedNegatives === 0 ? null : round($flaggedPositives / ($flaggedPositives + $flaggedNegatives), 4);

        return $result;
    }
}

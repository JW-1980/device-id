<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * Platt scaling: fits `p = sigmoid(a * score + b)` by Newton's method on held-out scores, with
 * Platt's smoothed targets so a perfectly separated set does not push `a` to infinity.
 */
final class Platt
{
    /**
     * @param  list<array{score: float, positive: bool, weight?: float}>  $items
     * @return array{a: float, b: float, fitted: bool} `fitted` false means the identity was returned
     */
    public static function fit(array $items, int $minimum = 20): array
    {
        $positives = count(array_filter($items, static fn (array $i): bool => $i['positive']));
        $negatives = count($items) - $positives;
        if (count($items) < $minimum || $positives === 0 || $negatives === 0) {
            return ['a' => 1.0, 'b' => 0.0, 'fitted' => false];
        }

        $hi = ($positives + 1.0) / ($positives + 2.0);
        $lo = 1.0 / ($negatives + 2.0);
        $a = 0.0;
        $b = log(($positives + 1.0) / ($negatives + 1.0));

        for ($iteration = 0; $iteration < 100; $iteration++) {
            $g = [0.0, 0.0];
            $h = [[1e-9, 0.0], [0.0, 1e-9]];
            foreach ($items as $item) {
                $w = $item['weight'] ?? 1.0;
                $p = LogisticModel::sigmoid($a * $item['score'] + $b);
                $t = $item['positive'] ? $hi : $lo;
                $d = $w * ($p - $t);
                $v = $w * $p * (1.0 - $p) + 1e-12;
                $g[0] += $d * $item['score'];
                $g[1] += $d;
                $h[0][0] += $v * $item['score'] * $item['score'];
                $h[0][1] += $v * $item['score'];
                $h[1][1] += $v;
            }
            $h[1][0] = $h[0][1];
            $det = $h[0][0] * $h[1][1] - $h[0][1] * $h[1][0];
            if (abs($det) < 1e-18) {
                break;
            }
            $da = ($h[1][1] * $g[0] - $h[0][1] * $g[1]) / $det;
            $db = (-$h[1][0] * $g[0] + $h[0][0] * $g[1]) / $det;
            $a -= $da;
            $b -= $db;
            if (abs($da) + abs($db) < 1e-12) {
                break;
            }
        }

        // A negative slope would invert the model's ranking; refuse it.
        if ($a <= 0.0) {
            return ['a' => 1.0, 'b' => 0.0, 'fitted' => false];
        }

        return ['a' => $a, 'b' => $b, 'fitted' => true];
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * L2-regularised logistic regression, trained by Newton-Raphson (iteratively reweighted least
 * squares) in pure PHP: no extension, no library, no GPU, deterministic to the last digit.
 *
 * - Sparse rows: a visit has a handful of non-zero features, so the Hessian is accumulated from
 *   outer products of the non-zero entries only and training scales with rows times the square
 *   of the non-zeros, not of the feature count.
 * - The intercept is not penalised.
 * - Sign constraint: a rule-hit feature may not carry a negative coefficient (a contradiction
 *   is never evidence of honesty). A violating feature is frozen at 0 and the fit repeated.
 * - `maxCoefficient` bounds every coefficient: with few honest rows a rule that never fired on
 *   honest data would otherwise be driven to an arbitrary size.
 */
final class LogisticTrainer
{
    /**
     * @param  list<TrainingRow>  $rows
     * @param  list<string>|null  $featureNames  default: every feature that is non-zero in at least one row
     * @return array{features: list<string>, coefficients: list<float>, intercept: float, frozen: list<string>, clipped: list<string>, iterations: int, converged: bool}
     */
    public static function fit(array $rows, float $lambda = 1.0, ?array $featureNames = null, float $maxCoefficient = 6.0, bool $balanceClasses = true, int $maxIterations = 60): array
    {
        if ($featureNames === null) {
            $seen = [];
            foreach ($rows as $row) {
                foreach ($row->features as $name => $value) {
                    if ($value !== 0.0) {
                        $seen[$name] = true;
                    }
                }
            }
            $featureNames = array_keys($seen);
            sort($featureNames);
        }

        $frozen = [];
        for ($round = 0; $round <= count($featureNames); $round++) {
            $active = array_values(array_diff($featureNames, $frozen));
            $result = self::newton($rows, $active, $lambda, $balanceClasses, $maxIterations);

            $violations = [];
            foreach ($active as $index => $name) {
                if (FeatureCatalogue::isRuleHit($name) && $result['beta'][$index] < 0.0) {
                    $violations[] = $name;
                }
            }
            if ($violations === []) {
                break;
            }
            array_push($frozen, ...$violations);
        }

        $clipped = [];
        $coefficients = [];
        foreach ($featureNames as $name) {
            $position = array_search($name, $active, true);
            $value = $position === false ? 0.0 : $result['beta'][$position];
            if (abs($value) > $maxCoefficient) {
                $clipped[] = $name;
                $value = $value > 0 ? $maxCoefficient : -$maxCoefficient;
            }
            $coefficients[] = $value;
        }

        sort($frozen);

        return [
            'features' => $featureNames, 'coefficients' => $coefficients, 'intercept' => $result['intercept'],
            'frozen' => $frozen, 'clipped' => $clipped, 'iterations' => $result['iterations'], 'converged' => $result['converged'],
        ];
    }

    /**
     * @param  list<TrainingRow>  $rows
     * @param  list<string>  $active
     * @return array{beta: list<float>, intercept: float, iterations: int, converged: bool}
     */
    private static function newton(array $rows, array $active, float $lambda, bool $balance, int $maxIterations): array
    {
        $index = array_flip($active);
        $p = count($active);
        $dim = $p + 1; // the last slot is the intercept

        $positiveWeight = $negativeWeight = 0.0;
        foreach ($rows as $row) {
            if ($row->isPositive()) {
                $positiveWeight += $row->labelWeight;
            } else {
                $negativeWeight += $row->labelWeight;
            }
        }
        $total = $positiveWeight + $negativeWeight;
        $classWeight = [
            true => $balance && $positiveWeight > 0 ? $total / (2 * $positiveWeight) : 1.0,
            false => $balance && $negativeWeight > 0 ? $total / (2 * $negativeWeight) : 1.0,
        ];

        $sparse = [];
        foreach ($rows as $row) {
            $entries = [];
            foreach ($row->features as $name => $value) {
                if (isset($index[$name]) && $value !== 0.0) {
                    $entries[] = [$index[$name], $value];
                }
            }
            $entries[] = [$p, 1.0];
            $sparse[] = [$entries, $row->isPositive() ? 1.0 : 0.0, $row->labelWeight * $classWeight[$row->isPositive()]];
        }

        $beta = array_fill(0, $dim, 0.0);
        $converged = false;
        $iterations = 0;
        for ($iterations = 1; $iterations <= $maxIterations; $iterations++) {
            $gradient = array_fill(0, $dim, 0.0);
            $hessian = array_fill(0, $dim, array_fill(0, $dim, 0.0));
            foreach ($sparse as [$entries, $y, $w]) {
                $z = 0.0;
                foreach ($entries as [$i, $v]) {
                    $z += $beta[$i] * $v;
                }
                $prob = LogisticModel::sigmoid($z);
                $residual = $w * ($prob - $y);
                $curvature = $w * $prob * (1.0 - $prob);
                foreach ($entries as [$i, $vi]) {
                    $gradient[$i] += $residual * $vi;
                    foreach ($entries as [$j, $vj]) {
                        $hessian[$i][$j] += $curvature * $vi * $vj;
                    }
                }
            }
            for ($i = 0; $i < $p; $i++) {
                $gradient[$i] += $lambda * $beta[$i];
                $hessian[$i][$i] += $lambda;
            }
            $hessian[$p][$p] += 1e-8;

            $step = self::solve($hessian, $gradient);
            $size = 0.0;
            for ($i = 0; $i < $dim; $i++) {
                $beta[$i] -= $step[$i];
                $size = max($size, abs($step[$i]));
            }
            if ($size < 1e-10) {
                $converged = true;
                break;
            }
        }

        return ['beta' => array_slice($beta, 0, $p), 'intercept' => $beta[$p], 'iterations' => min($iterations, $maxIterations), 'converged' => $converged];
    }

    /**
     * Solves `H x = g` for a symmetric positive-definite H by Cholesky decomposition.
     *
     * @param  list<list<float>>  $h
     * @param  list<float>  $g
     * @return list<float>
     */
    private static function solve(array $h, array $g): array
    {
        $n = count($g);
        $l = array_fill(0, $n, array_fill(0, $n, 0.0));
        for ($i = 0; $i < $n; $i++) {
            for ($j = 0; $j <= $i; $j++) {
                $sum = $h[$i][$j];
                for ($k = 0; $k < $j; $k++) {
                    $sum -= $l[$i][$k] * $l[$j][$k];
                }
                $l[$i][$j] = $i === $j ? sqrt(max($sum, 1e-12)) : $sum / $l[$j][$j];
            }
        }
        $y = array_fill(0, $n, 0.0);
        for ($i = 0; $i < $n; $i++) {
            $sum = $g[$i];
            for ($k = 0; $k < $i; $k++) {
                $sum -= $l[$i][$k] * $y[$k];
            }
            $y[$i] = $sum / $l[$i][$i];
        }
        $x = array_fill(0, $n, 0.0);
        for ($i = $n - 1; $i >= 0; $i--) {
            $sum = $y[$i];
            for ($k = $i + 1; $k < $n; $k++) {
                $sum -= $l[$k][$i] * $x[$k];
            }
            $x[$i] = $sum / $l[$i][$i];
        }

        return $x;
    }
}

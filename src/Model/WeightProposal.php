<?php

declare(strict_types=1);

namespace DeviceId\Model;

use DeviceId\CheckRegistry;

/**
 * Learned coefficients next to the shipped rule weights, for the owner to read and approve.
 * The runtime never applies these: they are a proposal for the `check_weights` override store.
 *
 * ## The mapping, and what it does not claim
 *
 * A coefficient is in log-odds; a rule weight is in the scorer's units. The proposal scales
 * the learned coefficients so that the LARGEST one among the rule hits equals the largest
 * shipped single weight among the hit rules that fired (45 for the shipped set): the ORDER and
 * the RATIOS are the learned information, the absolute level is an anchor the owner can move.
 * A rule that fired in fewer than {@see MIN_SUPPORT} rows has no evidence: its proposal is
 * `null` and the shipped weight stays. A bootstrap over groups (resampling machines or recipes,
 * not rows) gives a 5th-95th percentile interval; an interval that includes the shipped weight
 * means the data does not contradict it.
 */
final class WeightProposal
{
    public const MIN_SUPPORT = 5;

    public const ANCHOR_WEIGHT = 45;

    /**
     * @param  list<TrainingRow>  $rows  all rows (training and validation)
     * @param  array{features: list<string>, coefficients: list<float>}  $fit  the point fit
     * @return list<array{code: string, current: int, learned_coefficient: float, proposed: int|null, interval: array{0: int, 1: int}|null, fired_in_positive: int, fired_in_honest: int, note: string}>
     */
    public static function build(array $rows, array $fit, float $lambda = 1.0, int $bootstrap = 40, string $seed = 'device-id', float $maxCoefficient = 6.0): array
    {
        $coefficients = array_combine($fit['features'], $fit['coefficients']);
        $hitCoefficients = array_filter($coefficients, static fn (float $c, string $name): bool => FeatureCatalogue::isRuleHit($name) && $c > 0.0, ARRAY_FILTER_USE_BOTH);
        $max = $hitCoefficients === [] ? 0.0 : max($hitCoefficients);
        $scale = $max > 0.0 ? self::ANCHOR_WEIGHT / $max : 0.0;

        $support = ['pos' => [], 'neg' => []];
        foreach ($rows as $row) {
            foreach ($row->features as $name => $value) {
                if ($value !== 0.0) {
                    $support[$row->isPositive() ? 'pos' : 'neg'][$name] = ($support[$row->isPositive() ? 'pos' : 'neg'][$name] ?? 0) + 1;
                }
            }
        }

        $intervals = self::bootstrap($rows, $fit['features'], $scale, $lambda, $bootstrap, $seed, $maxCoefficient);

        $out = [];
        foreach (CheckRegistry::codes() as $code) {
            $feature = FeatureCatalogue::HIT_PREFIX.$code;
            $pos = $support['pos'][$feature] ?? 0;
            $neg = $support['neg'][$feature] ?? 0;
            $coefficient = $coefficients[$feature] ?? 0.0;
            $enough = $pos + $neg >= self::MIN_SUPPORT;
            $proposed = $enough && $scale > 0.0 ? max(0, min(60, (int) round($coefficient * $scale))) : null;

            $note = match (true) {
                ! $enough => 'insufficient evidence: fired in '.($pos + $neg).' rows (need '.self::MIN_SUPPORT.')',
                $neg === 0 && $pos > 0 => 'never fired on honest rows in this data; the level is set by the positives and the regularisation only',
                $pos === 0 => 'fired only on honest rows: the data suggests a false-positive source',
                default => '',
            };

            $out[] = [
                'code' => $code,
                'current' => CheckRegistry::describe()[$code]['default_weight'],
                'learned_coefficient' => round($coefficient, 4),
                'proposed' => $proposed,
                'interval' => $enough ? ($intervals[$feature] ?? null) : null,
                'fired_in_positive' => $pos,
                'fired_in_honest' => $neg,
                'note' => $note,
            ];
        }

        usort($out, static fn (array $a, array $b): int => ($b['fired_in_positive'] + $b['fired_in_honest']) <=> ($a['fired_in_positive'] + $a['fired_in_honest']) ?: strcmp($a['code'], $b['code']));

        return $out;
    }

    /**
     * @param  list<TrainingRow>  $rows
     * @param  list<string>  $features
     * @return array<string, array{0: int, 1: int}>
     */
    private static function bootstrap(array $rows, array $features, float $scale, float $lambda, int $draws, string $seed, float $maxCoefficient): array
    {
        if ($scale <= 0.0 || $draws < 2 || count($rows) > 5000) {
            return [];
        }

        $groups = [];
        foreach ($rows as $row) {
            $groups[$row->group][] = $row;
        }
        $names = array_keys($groups);
        sort($names);
        mt_srand((int) hexdec(substr(hash('sha256', $seed), 0, 7)));

        $samples = [];
        for ($draw = 0; $draw < $draws; $draw++) {
            $resample = [];
            for ($i = 0, $n = count($names); $i < $n; $i++) {
                array_push($resample, ...$groups[$names[mt_rand(0, $n - 1)]]);
            }
            $positives = count(array_filter($resample, static fn (TrainingRow $r): bool => $r->isPositive()));
            if ($positives === 0 || $positives === count($resample)) {
                continue;
            }
            $fit = LogisticTrainer::fit($resample, $lambda, $features, $maxCoefficient);
            foreach ($fit['features'] as $index => $name) {
                $samples[$name][] = max(0, min(60, (int) round($fit['coefficients'][$index] * $scale)));
            }
        }

        $intervals = [];
        foreach ($samples as $name => $values) {
            if (count($values) < 5) {
                continue;
            }
            sort($values);
            $intervals[$name] = [$values[(int) floor(0.05 * (count($values) - 1))], $values[(int) ceil(0.95 * (count($values) - 1))]];
        }

        return $intervals;
    }
}

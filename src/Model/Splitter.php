<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * Splits rows by LINKED UNIT, never by row: every row connected to another through its `group`
 * (a device, or on single-machine harness data a machine plus a recipe) or through one of its
 * `links` (the keyed account group) lands on one side, so the model is always judged on devices,
 * accounts and evasion recipes it has not seen.
 *
 * ## Why the unit is the union of device and account linkage (skeptical review M8)
 *
 * Labels are per account (a ban covers the account), while `group` is per device. Split by device
 * alone, one fraudster's visits from a laptop and a phone, or a protected browser's visits (a new
 * random device key per visit), could sit on both sides and report a leak as accuracy. The units
 * are the connected components of the graph whose edges are "same group" and "same link"
 * ({@see components()}), computed with union-find.
 *
 * ## Three sides
 *
 * {@see threeWay()} returns train / calibration / validation: the model is FITTED on train, its
 * Platt calibration and the rules' calibration are fitted on calibration, and every reported
 * metric and promotion criterion is measured on validation, which neither touched. Calibrating
 * and measuring on the same rows made ECE in-sample. {@see byGroup()} is the two-way form.
 */
final class Splitter
{
    /**
     * @param  list<TrainingRow>  $rows
     * @return array{train: list<TrainingRow>, validation: list<TrainingRow>, groups: array{train: list<string>, validation: list<string>}}
     */
    public static function byGroup(array $rows, float $validationFraction = 0.3, string $seed = 'device-id'): array
    {
        $split = self::split($rows, ['validation' => $validationFraction], $seed);

        return [
            'train' => $split['train'],
            'validation' => $split['validation'],
            'groups' => ['train' => $split['groups']['train'], 'validation' => $split['groups']['validation']],
        ];
    }

    /**
     * @param  list<TrainingRow>  $rows
     * @return array{train: list<TrainingRow>, calibration: list<TrainingRow>, validation: list<TrainingRow>, groups: array{train: list<string>, calibration: list<string>, validation: list<string>}}
     */
    public static function threeWay(array $rows, float $calibrationFraction = 0.25, float $validationFraction = 0.25, string $seed = 'device-id'): array
    {
        $split = self::split($rows, ['validation' => $validationFraction, 'calibration' => $calibrationFraction], $seed);

        return [
            'train' => $split['train'],
            'calibration' => $split['calibration'],
            'validation' => $split['validation'],
            'groups' => ['train' => $split['groups']['train'], 'calibration' => $split['groups']['calibration'], 'validation' => $split['groups']['validation']],
        ];
    }

    /**
     * The linked units: connected components over "same group" and "same link", each a list of
     * row indexes, keyed by the smallest group name in the component (stable across runs).
     *
     * @param  list<TrainingRow>  $rows
     * @return array<string, list<int>>
     */
    public static function components(array $rows): array
    {
        $parent = [];
        $find = static function (string $node) use (&$parent, &$find): string {
            while ($parent[$node] !== $node) {
                $parent[$node] = $parent[$parent[$node]];
                $node = $parent[$node];
            }

            return $node;
        };
        $union = static function (string $a, string $b) use (&$parent, $find): void {
            $ra = $find($a);
            $rb = $find($b);
            if ($ra !== $rb) {
                // Deterministic root: the lexically smaller node.
                [$keep, $drop] = strcmp($ra, $rb) <= 0 ? [$ra, $rb] : [$rb, $ra];
                $parent[$drop] = $keep;
            }
        };

        foreach ($rows as $row) {
            $groupNode = 'g:'.$row->group;
            $parent[$groupNode] ??= $groupNode;
            foreach ($row->links as $link) {
                $linkNode = 'l:'.$link;
                $parent[$linkNode] ??= $linkNode;
                $union($groupNode, $linkNode);
            }
        }

        $byRoot = [];
        $names = [];
        foreach ($rows as $index => $row) {
            $root = $find('g:'.$row->group);
            $byRoot[$root][] = $index;
            $names[$root] = isset($names[$root]) ? min($names[$root], $row->group) : $row->group;
        }

        $out = [];
        foreach ($byRoot as $root => $indexes) {
            $out[$names[$root]] = $indexes;
        }
        ksort($out, SORT_STRING);

        return $out;
    }

    /**
     * @param  list<TrainingRow>  $rows
     * @param  array<string, float>  $fractions  held-out side => fraction of rows, filled in this order
     * @return array{train: list<TrainingRow>, calibration: list<TrainingRow>, validation: list<TrainingRow>, groups: array<string, list<string>>}
     */
    private static function split(array $rows, array $fractions, string $seed): array
    {
        $components = self::components($rows);
        $names = array_keys($components);
        usort($names, static fn (string $a, string $b): int => strcmp(hash('sha256', $seed.'|'.$a), hash('sha256', $seed.'|'.$b)));

        $side = [];
        $cursor = 0;
        foreach ($fractions as $name => $fraction) {
            $target = (int) ceil(count($rows) * $fraction);
            $count = 0;
            while ($cursor < count($names) && $count < $target) {
                $side[$names[$cursor]] = $name;
                $count += count($components[$names[$cursor]]);
                $cursor++;
            }
        }

        // Every held-out side needs both classes, or neither calibration nor the held-out metrics
        // mean anything: borrow a component of the missing class from train when one exists.
        foreach (array_keys($fractions) as $held) {
            foreach ([true, false] as $positive) {
                if (self::sideHas($components, $rows, $side, $held, $positive)) {
                    continue;
                }
                $inTrain = array_values(array_filter($names, static fn (string $name): bool => ($side[$name] ?? 'train') === 'train' && self::componentHas($components[$name], $rows, $positive)));
                // Train keeps at least one component of each class: a model needs both to fit.
                if (count($inTrain) < 2) {
                    continue;
                }
                $side[$inTrain[0]] = $held;
            }
        }

        $out = ['train' => [], 'calibration' => [], 'validation' => [], 'groups' => ['train' => [], 'calibration' => [], 'validation' => []]];
        foreach ($names as $name) {
            $target = $side[$name] ?? 'train';
            foreach ($components[$name] as $index) {
                $out[$target][] = $rows[$index];
                $out['groups'][$target][$rows[$index]->group] = true;
            }
        }
        foreach ($out['groups'] as $target => $groups) {
            $list = array_keys($groups);
            sort($list, SORT_STRING);
            $out['groups'][$target] = array_map('strval', $list);
        }

        return $out;
    }

    /**
     * @param  array<string, list<int>>  $components
     * @param  list<TrainingRow>  $rows
     * @param  array<string, string>  $side
     */
    private static function sideHas(array $components, array $rows, array $side, string $held, bool $positive): bool
    {
        foreach ($side as $name => $target) {
            if ($target === $held && self::componentHas($components[$name], $rows, $positive)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<int>  $indexes
     * @param  list<TrainingRow>  $rows
     */
    private static function componentHas(array $indexes, array $rows, bool $positive): bool
    {
        foreach ($indexes as $index) {
            if ($rows[$index]->isPositive() === $positive) {
                return true;
            }
        }

        return false;
    }
}

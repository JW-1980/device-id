<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * Splits rows into training and validation by GROUP, never by row: every row of a group (a
 * machine, or on single-machine harness data a machine plus a recipe) lands on one side, so
 * the model is always judged on machines or evasion recipes it has not seen. A row-level split
 * would put the same browser on both sides and report a leak as accuracy.
 */
final class Splitter
{
    /**
     * @param  list<TrainingRow>  $rows
     * @return array{train: list<TrainingRow>, validation: list<TrainingRow>, groups: array{train: list<string>, validation: list<string>}}
     */
    public static function byGroup(array $rows, float $validationFraction = 0.3, string $seed = 'device-id'): array
    {
        $groups = [];
        foreach ($rows as $row) {
            $groups[$row->group][] = $row;
        }
        $names = array_keys($groups);
        usort($names, static fn (string $a, string $b): int => strcmp(hash('sha256', $seed.'|'.$a), hash('sha256', $seed.'|'.$b)));

        $target = (int) ceil(count($rows) * $validationFraction);
        $validation = [];
        $count = 0;
        foreach ($names as $name) {
            if ($count >= $target) {
                break;
            }
            $validation[$name] = true;
            $count += count($groups[$name]);
        }

        // Both sides need both classes, or neither calibration nor the held-out metrics mean anything.
        foreach ([true, false] as $positive) {
            $hasIn = static function (array $set) use ($groups, $positive): bool {
                foreach ($set as $name => $_) {
                    foreach ($groups[$name] as $row) {
                        if ($row->isPositive() === $positive) {
                            return true;
                        }
                    }
                }

                return false;
            };
            if (! $hasIn($validation)) {
                foreach ($names as $name) {
                    if (isset($validation[$name])) {
                        continue;
                    }
                    foreach ($groups[$name] as $row) {
                        if ($row->isPositive() === $positive) {
                            $validation[$name] = true;
                            break 2;
                        }
                    }
                }
            }
        }

        $train = $val = [];
        $trainGroups = $valGroups = [];
        foreach ($names as $name) {
            if (isset($validation[$name])) {
                array_push($val, ...$groups[$name]);
                $valGroups[] = $name;
            } else {
                array_push($train, ...$groups[$name]);
                $trainGroups[] = $name;
            }
        }
        sort($trainGroups);
        sort($valGroups);

        return ['train' => $train, 'validation' => $val, 'groups' => ['train' => $trainGroups, 'validation' => $valGroups]];
    }
}

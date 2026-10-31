<?php

declare(strict_types=1);

namespace DeviceId\Feedback;

use DeviceId\Model\TrainingRow;
use DeviceId\Model\TrainingRowBuilder;

/**
 * Turns the reports on one subject into the label the trainer sees, with minFraud's semantics:
 *
 * - The LAST report wins (by `reportedAt`, ties by the order given), so an admin correcting
 *   himself is obeyed.
 * - `clear` retracts everything before it: no label stands, the rows are not trained on.
 * - `not_abuse` becomes `honest` with weight 1; `confirmed_fraud` the abuse kind with weight 1;
 *   `suspected` the abuse kind with weight 0.5.
 *
 * {@see relabelRows()} applies a resolution to the stored training rows of that subject in the
 * week it was reported, which is how a false-positive report lowers the weight of the positive
 * rows it contradicts ("reduce false positives") and a `clear` removes a label that was wrong.
 */
final class FeedbackResolver
{
    /**
     * @param  list<FeedbackReport>  $reports
     * @param  string  $abuseKind  the {@see TrainingRow::LABELS} entry a positive report stands for (`fraud`, `automation`, `headless`, `spoof`)
     */
    public static function resolve(array $reports, string $abuseKind = 'fraud'): FeedbackResolution
    {
        if ($abuseKind === 'honest' || ! in_array($abuseKind, TrainingRow::LABELS, true)) {
            throw new \InvalidArgumentException("'{$abuseKind}' is not an abuse kind");
        }
        $ordered = [];
        foreach ($reports as $index => $report) {
            $ordered[] = [$report->reportedAt, $index, $report];
        }
        usort($ordered, static fn (array $a, array $b): int => [$a[0], $a[1]] <=> [$b[0], $b[1]]);
        if ($ordered === []) {
            return new FeedbackResolution(null, null, 0.0, 0, false);
        }

        /** @var FeedbackReport $last */
        $last = $ordered[count($ordered) - 1][2];

        return match ($last->label) {
            FeedbackLabel::CONFIRMED_FRAUD => new FeedbackResolution($last->label, $abuseKind, 1.0, count($ordered), false),
            FeedbackLabel::SUSPECTED => new FeedbackResolution($last->label, $abuseKind, 0.5, count($ordered), false),
            FeedbackLabel::NOT_ABUSE => new FeedbackResolution($last->label, 'honest', 1.0, count($ordered), false),
            default => new FeedbackResolution(null, null, 0.0, count($ordered), true),
        };
    }

    /**
     * The rows of ONE device group in ONE observed week, relabelled by the resolution; every
     * other row is returned as it was. A row's `source` records that a human decided
     * (`feedback`); nothing else about the row changes, and the note never enters it.
     *
     * @param  list<array<string, mixed>>  $rows  training rows as {@see TrainingRowBuilder} builds them
     * @return list<array<string, mixed>>
     */
    public static function relabelRows(array $rows, string $group, string $observedWeek, FeedbackResolution $resolution): array
    {
        if ($resolution->reports === 0) {
            return $rows;
        }
        foreach ($rows as $index => $row) {
            if (($row['group'] ?? null) !== $group || ($row['observed_week'] ?? null) !== $observedWeek) {
                continue;
            }
            $rows[$index]['label'] = $resolution->trainingLabel;
            $rows[$index]['label_weight'] = $resolution->labelWeight;
            $rows[$index]['source'] = 'feedback';
        }

        return $rows;
    }
}

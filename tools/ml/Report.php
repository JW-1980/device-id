<?php

declare(strict_types=1);

namespace DeviceId\Ml;

use DeviceId\Model\WeightProposal;

/**
 * Markdown renderers for the training and evaluation reports.
 */
final class Report
{
    /**
     * @param  array<string, mixed>  $document
     * @param  array<string, mixed>  $report
     * @param  list<array<string, mixed>>  $proposal
     */
    public static function training(array $document, array $report, array $proposal, int $rows): string
    {
        $out = "# Model training report\n\n";
        $out .= "- model: `{$document['model_id']}` (schema {$document['schema']}, {$document['kind']}), trained {$document['trained_at']}\n";
        $out .= "- training set sha256: `{$document['training_set_sha256']}`; rows: {$rows} (train {$document['split']['train_rows']}, validation {$document['split']['validation_rows']})\n";
        $out .= "- split unit: {$document['split']['unit']}; validation groups: ".count($document['split']['validation_groups'])."\n";
        $out .= '- calibration: Platt a='.round($document['calibration']['a'], 4).', b='.round($document['calibration']['b'], 4).($document['calibration']['fitted'] ? '' : ' (NOT fitted: validation too small, identity used)').", calibrated to {$document['calibration']['calibrated_to']}\n";
        $out .= '- coefficients frozen at 0 (negative rule hit): '.(implode(', ', $document['training']['frozen_at_zero']) ?: 'none').'; clipped: '.(implode(', ', $document['training']['clipped']) ?: 'none')."\n";
        $out .= '- converged: '.($document['training']['converged'] ? 'yes' : 'NO').", iterations {$document['training']['iterations']}\n\n";
        $out .= "## Held-out evaluation (validation groups only)\n\n".self::sliceTable($report['held_out']);
        $out .= "\n## Learned weights against the shipped weights\n\n";
        $out .= 'Proposal only; nothing applies it. Scale: the largest learned rule-hit coefficient maps to '.WeightProposal::ANCHOR_WEIGHT.". Interval: bootstrap over groups, 5th-95th percentile.\n\n";
        $out .= "| rule | current | learned coef | proposed | interval | fired (non-honest / honest) | note |\n|---|---|---|---|---|---|---|\n";
        foreach (array_slice($proposal, 0, 40) as $row) {
            $out .= sprintf("| %s | %d | %s | %s | %s | %d / %d | %s |\n", $row['code'], $row['current'], $row['learned_coefficient'], $row['proposed'] ?? 'n/a', $row['interval'] === null ? 'n/a' : '['.$row['interval'][0].', '.$row['interval'][1].']', $row['fired_in_positive'], $row['fired_in_honest'], $row['note']);
        }

        return $out;
    }

    /**
     * @param  array<string, array<string, mixed>>  $slices
     */
    public static function sliceTable(array $slices): string
    {
        $fmt = static fn (mixed $v): string => $v === null ? 'n/a' : (string) $v;
        $out = "| slice | n | non-honest | honest | rules recall@challenge | rules FPR@challenge | rules AUC | model recall@0.5 | model FPR@0.5 | model AUC | model ECE |\n|---|---|---|---|---|---|---|---|---|---|---|\n";
        foreach ($slices as $name => $s) {
            $m = $s['model'] ?? null;
            $out .= sprintf(
                "| %s | %d | %d | %d | %s | %s | %s | %s | %s | %s | %s |\n",
                $name, $s['n'], $s['positives'], $s['negatives'],
                $fmt($s['rules']['recall_at_flag']), $fmt($s['rules']['false_positive_rate_at_flag']), $fmt($s['rules']['auc']),
                $fmt($m['recall_at_flag'] ?? null), $fmt($m['false_positive_rate_at_flag'] ?? null), $fmt($m['auc'] ?? null), $fmt($m['ece'] ?? null),
            );
        }
        $out .= "\nrecall/FPR for the rules are at the shipped `challenge` band (score 60); for the model at p = 0.5. `n/a` = no rows of that class in the slice (a rate is unknown, not zero).\n";

        $all = $slices['all'];
        $out .= "\n### Precision and recall at fixed false-positive rates (all rows of the set)\n\n| FPR target | system | threshold | recall | precision | actual FPR | honest rows | resolution-limited |\n|---|---|---|---|---|---|---|---|\n";
        foreach (['rules', 'model'] as $system) {
            foreach ($all[$system]['at_fpr'] ?? [] as $point) {
                $out .= sprintf("| %s | %s | %s | %s | %s | %s | %d | %s |\n", $point['fpr_target'], $system, $fmt($point['threshold']), $fmt($point['recall']), $fmt($point['precision']), $fmt($point['fpr']), $point['negatives'], $point['resolution_limited'] ? 'yes: fewer honest rows than 1/target' : 'no');
            }
        }

        return $out;
    }

    /**
     * @param  array<string, array<string, mixed>>  $slices
     */
    public static function evaluation(string $title, array $slices, string $note): string
    {
        return "# {$title}\n\n{$note}\n\n".self::sliceTable($slices);
    }
}

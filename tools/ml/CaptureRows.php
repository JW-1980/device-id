<?php

declare(strict_types=1);

namespace DeviceId\Ml;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\Model\FeatureCatalogue;
use DeviceId\Model\TrainingRow;

require_once __DIR__.'/../capture/CaptureAnalysis.php';

/**
 * Capture-harness dataset records as training rows.
 *
 * A dataset record holds what the browser said (claims, request headers, labels); the ENGINE
 * is run here, so a row always reflects the current rules and a stale recording can never
 * train a model. The row keeps features and slice labels only.
 *
 * The group key is `machine|browser|mode|variant`. On a single-machine harness the machine id
 * alone would put every row in one group and make a held-out split impossible; with the
 * recipe in the key each evasion recipe is held out as a unit, so validation measures
 * generalisation to a recipe the model has not seen. With data from three or more machines
 * hosts group by machine only (`machineOnly: true`).
 */
final class CaptureRows
{
    /**
     * @param  array<string, mixed>  $record
     */
    public static function fromRecord(array $record, bool $machineOnly = false): TrainingRow
    {
        $analysis = CaptureAnalysis::analyse($record);
        $merged = $analysis['merged'];
        $keys = $analysis['keys'];

        $disagreements = [];
        foreach ($merged['codes'] as $code => $meta) {
            $disagreements[] = ['code' => (string) $code, 'detail' => (string) $meta['detail'], 'weight' => (int) $meta['weight']];
        }

        $protected = (bool) ($keys['protected'] ?? false);
        $features = FeatureCatalogue::build(
            $disagreements,
            count($merged['integrity_codes']),
            (int) $merged['confidence']['score'],
            count($keys['untrusted'] ?? []),
            0,
            $protected,
        );

        $engine = (string) ($record['browser']['engine'] ?? 'unknown');
        $touch = $keys['components']['touch'] ?? null;
        $group = $machineOnly
            ? (string) $record['machine']['id']
            : implode('|', [$record['machine']['id'], $record['browser']['name'], $record['browser']['mode'], $record['browser']['variant']]);

        return new TrainingRow(
            $features,
            (string) $record['labels']['class'],
            $group,
            [
                'engine' => in_array($engine, ['chromium', 'gecko', 'webkit'], true) ? $engine : 'unknown',
                'device' => $touch === null ? 'unknown' : ($touch === 1 ? 'mobile' : 'desktop'),
                'privacy' => $protected ? 'protected' : 'none',
            ],
            (int) $merged['total_weight'],
            1.0,
            'capture-harness',
            (string) $record['id'],
        );
    }

    /**
     * @param  list<string>  $directories  directories of dataset records (`*.json`)
     * @return array{rows: list<TrainingRow>, files: list<string>, sha256: string}
     */
    public static function load(array $directories, bool $machineOnly = false): array
    {
        CaptureAnalysis::configure();
        $files = [];
        foreach ($directories as $directory) {
            foreach (glob(rtrim($directory, '/').'/*.json') ?: [] as $file) {
                $files[] = $file;
            }
        }
        sort($files);

        $rows = [];
        $hash = hash_init('sha256');
        foreach ($files as $file) {
            $raw = (string) file_get_contents($file);
            $record = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
            if (($record['schema'] ?? null) !== CaptureAnalysis::DATASET_SCHEMA || ! in_array($record['labels']['class'] ?? null, TrainingRow::LABELS, true)) {
                continue;
            }
            hash_update($hash, basename($file)."\0".$raw);
            $rows[] = self::fromRecord($record, $machineOnly);
        }

        return ['rows' => $rows, 'files' => $files, 'sha256' => hash_final($hash)];
    }
}

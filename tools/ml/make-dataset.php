<?php

declare(strict_types=1);

/**
 * Turns raw harness runs (tools/capture/capture.mjs or tools/ml/variants.mjs) into dataset
 * records.
 *
 *   php tools/ml/make-dataset.php <runs-dir> <out-dir>
 *
 * Unlike engine-report.php this applies no expectations: the spoof class has none, and the
 * point here is the labelled record, not a pass/fail.
 */
require __DIR__.'/../../src/autoload.php';
require __DIR__.'/../capture/CaptureAnalysis.php';

use DeviceId\Capture\CaptureAnalysis;

[$in, $out] = [$argv[1] ?? null, $argv[2] ?? null];
if ($in === null || $out === null || ! is_dir($in)) {
    fwrite(STDERR, "usage: php tools/ml/make-dataset.php <runs-dir> <out-dir>\n");
    exit(2);
}
@mkdir($out, 0777, true);
$written = $skipped = 0;
foreach (glob(rtrim($in, '/').'/*.json') ?: [] as $file) {
    $run = json_decode((string) file_get_contents($file), true, 64, JSON_THROW_ON_ERROR);
    if (! ($run['complete'] ?? false)) {
        $skipped++;

        continue;
    }
    $record = CaptureAnalysis::toDataset($run);
    file_put_contents($out.'/'.$record['id'].'.json', json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n");
    $written++;
}
echo "wrote {$written} dataset records to {$out}, skipped {$skipped} incomplete\n";

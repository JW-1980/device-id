<?php

declare(strict_types=1);

/**
 * Prints the engine's default method policy (`ProbeRegistry::disabled()` with no settings) and
 * the probe set as JSON, so the capture server's challenge answers exactly what a host with
 * default settings would.
 */
require __DIR__.'/../../src/autoload.php';

use DeviceId\ProbeRegistry;

echo json_encode([
    'disabled_probes' => ProbeRegistry::disabled(),
    'probe_set' => ProbeRegistry::PROBE_SET,
], JSON_THROW_ON_ERROR), "\n";

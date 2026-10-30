<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Support;

/**
 * Where a package reads the previous observation from.
 *
 * ## Why the package declares this instead of querying
 *
 * Because the package must not know what a database is. Its whole claim is that it runs in a
 * host with no framework, no container and — for a host that wants nothing else — no database
 * at all. A class that issued queries would make PDO a requirement of the *rules*, and the
 * rules are the part that has to be trustworthy in any host.
 *
 * So the package declares the narrowest reader that makes `TemporalConsistency` work, and a
 * host supplies the adapter. The application already has the rows; the adapter is a two-column
 * SELECT.
 *
 * ## Returning null is a real answer
 *
 * "No previous observation for this device" is what a first-time visitor looks like, and the
 * rule must stay silent for them: missing data is never evidence. An adapter that threw on
 * "not found" would turn every new visitor into an error path.
 */
interface ObservationReader
{
    /**
     * The most recent previous observation for a device, or null when there is none.
     *
     * Newest first, and only one is needed — the rule compares against the immediately
     * preceding observation, not against the history.
     */
    public function latestFor(int $deviceId): ?PreviousObservation;
}

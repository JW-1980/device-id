<?php

declare(strict_types=1);

namespace DeviceId\Envelope;

/**
 * The two envelope slots a challenge nonce is redeemed for: tier 1 (sent at once) and tier 2
 * (the slower probes, sent after tier 1 succeeded). A nonce is redeemed at most once per slot.
 *
 * The wire values. They used to be constants on the application's `FingerprintChallenge`,
 * which the envelope parser read; the parser moved into this package on 2026-10-21 and the
 * application's challenge now declares its constants as these.
 */
final class Slot
{
    public const TIER1 = 'tier1';

    public const TIER2 = 'tier2';

    public const ALL = [self::TIER1, self::TIER2];
}

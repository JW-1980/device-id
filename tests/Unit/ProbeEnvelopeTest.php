<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Support\ProbeEnvelope;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The one reader of the client's probe envelope (round-2 CQ-17: three unwrappers with
 * three semantics, two of which never matched the live wire format).
 */
final class ProbeEnvelopeTest extends TestCase
{
    #[Test]
    public function a_live_failure_envelope_has_no_value_and_unwraps_to_null(): void
    {
        // The v3 collector sends `{state: 'unavailable'|'error', ...}` without `value`.
        self::assertNull(ProbeEnvelope::unwrap(['state' => 'unavailable']));
        self::assertNull(ProbeEnvelope::unwrap(['state' => 'error', 'error' => 'TypeError']));
        self::assertTrue(ProbeEnvelope::isFailed(['state' => 'unavailable']));
        self::assertTrue(ProbeEnvelope::isFailed(['state' => 'error', 'value' => 'ignored']));
    }

    #[Test]
    public function a_wrapped_ok_value_and_a_bare_value_both_unwrap_to_the_value(): void
    {
        self::assertSame('0101', ProbeEnvelope::unwrap(['state' => 'ok', 'value' => '0101']), 'the v2 shape');
        self::assertSame(['a' => 1], ProbeEnvelope::unwrap(['a' => 1]), 'a bare value passes through');
        self::assertSame('raw', ProbeEnvelope::unwrap('raw'));
        self::assertNull(ProbeEnvelope::unwrap(null));
        self::assertFalse(ProbeEnvelope::isFailed(['state' => 'ok', 'value' => 1]));
        self::assertFalse(ProbeEnvelope::isFailed('raw'));
    }

    #[Test]
    public function an_ok_envelope_without_a_value_key_is_the_node_itself(): void
    {
        $node = ['state' => 'ok', 'width' => 1920, 'height' => 1080];

        self::assertSame($node, ProbeEnvelope::unwrap($node));
    }

    #[Test]
    public function a_claim_that_merely_contains_a_state_field_is_not_an_envelope(): void
    {
        $node = ['state' => 'granted', 'name' => 'geolocation'];

        self::assertSame($node, ProbeEnvelope::unwrap($node), 'an unrecognised state is data, not an envelope');
        self::assertFalse(ProbeEnvelope::isFailed($node));
        self::assertFalse(ProbeEnvelope::isFailed(['state' => 7]));
        self::assertSame(['state' => 7], ProbeEnvelope::unwrap(['state' => 7]));
    }
}

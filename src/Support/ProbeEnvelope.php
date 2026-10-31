<?php

declare(strict_types=1);

namespace DeviceId\Support;

/**
 * The ONE reader of the client's probe envelope.
 *
 * The collector (`resources/js/collector/index.ts`, `resolveAll`) sends a probe
 * that succeeded as its raw value and a probe that did not as `{state: 'unavailable'|'error',
 * …}` — a `state` key and NO `value` key. An older shape, `{state, value}`, is still read for
 * the v2 fixtures and the parity gate. Until this class existed the envelope was unwrapped in
 * three places with three semantics (code-quality review CQ-17): two required `{state, value}`
 * and therefore never matched the live wire format, one treated any `state` key as a failure.
 *
 * - {@see unwrap()}: the value a consumer reads. A failed envelope is `null`; an `ok`
 *   envelope yields its `value` (or the node itself when the client sent `{state: 'ok'}`
 *   next to the payload keys); anything without a recognised `state` passes through, so a
 *   claim that happens to contain a field called `state` is not swallowed.
 * - {@see isFailed()}: whether the node is a non-`ok` envelope, for coverage.
 *
 * Framework-free. Lives only in this package since the one-engine migration (2026-10-21);
 * the application uses this class.
 */
final class ProbeEnvelope
{
    public const STATE_OK = 'ok';

    /** @var list<string> */
    public const STATES = ['ok', 'unavailable', 'error'];

    /**
     * The probe's value, or null for a non-`ok` envelope.
     */
    public static function unwrap(mixed $node): mixed
    {
        if (! is_array($node) || ! array_key_exists('state', $node)) {
            return $node;
        }

        $state = $node['state'];
        if (! is_string($state) || ! in_array($state, self::STATES, true)) {
            return $node;
        }

        if ($state !== self::STATE_OK) {
            return null;
        }

        return array_key_exists('value', $node) ? $node['value'] : $node;
    }

    /**
     * Whether the node is an envelope whose state is not `ok` (the client ran the probe and
     * it declined or threw).
     */
    public static function isFailed(mixed $node): bool
    {
        if (! is_array($node) || ! array_key_exists('state', $node)) {
            return false;
        }

        $state = $node['state'];

        return is_string($state) && in_array($state, self::STATES, true) && $state !== self::STATE_OK;
    }
}

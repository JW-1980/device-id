<?php

declare(strict_types=1);

namespace DeviceId;

/**
 * Deterministic canonical serialisation. The copy here is authoritative.
 *
 * ## Why this exists at all, given `json_encode` will do
 *
 * Three concrete ways a naive canonicalisation silently merges two different environments
 * into one key, each of which would make the fraud surface blind to a real difference:
 *
 * 1. **Types collide.** A device reporting `hardwareConcurrency` as `1` and one reporting
 *    `"1"` would hash the same. JSON preserves that difference; any hand-rolled serialiser
 *    that does `String($value)` throws it away.
 * 2. **Nested objects are not sorted.** `ksort($claims)` sorts the top level only. Two
 *    devices whose nested blocks list the same extensions in a different order would derive
 *    the same key.
 * 3. **Absent and null are indistinguishable.** `json_encode(['a' => null])` and
 *    `json_encode([])` are both valid claims of "nothing here", but here they mean
 *    different things: *the probe returned null* and *the probe did not run*.
 *
 * So every leaf is type-tagged, keys are sorted recursively, and **list order is preserved**,
 * because in several probes the order *is* the signal (font resolution order, codec list
 * order, the Sec-Fetch family).
 *
 * ## Why the client also has one
 *
 * The browser collector keeps a copy for its own determinism tests. **This one decides**:
 * the digest and the device key are computed here, so there is no question of the two
 * disagreeing. That was the point of moving the digest server-side.
 *
 * ## A known limitation, stated rather than papered over
 *
 * An empty list and an empty map are different claims, and PHP cannot tell them apart — both
 * are `[]` after `json_decode`. JSON's `{}` and `[]` decode identically, so the distinction is
 * unrecoverable at this layer. It is harmless because no probe in the catalogue emits an
 * empty *map* where the distinction would carry meaning, and that is a property of the probe
 * set rather than a guarantee of the format.
 */
final class Canonicaliser
{
    public static function canonicalise(mixed $value): string
    {
        if ($value === null) {
            return 'n';
        }

        if (is_bool($value)) {
            return $value ? 'b1' : 'b0';
        }

        if (is_int($value)) {
            return 'd:i'.$value;
        }

        if (is_float($value)) {
            return self::canonicaliseFloat($value);
        }

        if (is_string($value)) {
            return 's:'.$value;
        }

        if ($value === []) {
            return 'l:0';
        }

        if (is_array($value)) {
            return array_is_list($value)
                ? self::canonicaliseList($value)
                : self::canonicaliseMap($value);
        }

        // Objects and resources never reach here from JSON, but a caller passing one should
        // not get a silently wrong key.
        return 'x:'.get_debug_type($value);
    }

    /**
     * @param  array<mixed>  $value
     */
    private static function canonicaliseList(array $value): string
    {
        $parts = [];
        foreach ($value as $item) {
            $parts[] = self::canonicalise($item);
        }

        return 'l:'.count($parts).'['.implode(',', $parts).']';
    }

    /**
     * @param  array<array-key, mixed>  $value
     */
    private static function canonicaliseMap(array $value): string
    {
        $keys = array_map(strval(...), array_keys($value));
        sort($keys, SORT_STRING);

        $parts = [];
        foreach ($keys as $key) {
            $parts[] = json_encode($key, JSON_THROW_ON_ERROR).':'.self::canonicalise($value[$key]);
        }

        return 'm:{'.implode(',', $parts).'}';
    }

    /**
     * `%.17G` is the shortest representation that round-trips an IEEE-754 double, so two
     * devices reporting the same audio sum produce the same string. The int/float
     * distinction is preserved by the `d:i` / `d:f` tag, so a device reporting `1.0` and
     * one reporting `1` get different keys — a difference `json_decode` would have thrown
     * away.
     */
    private static function canonicaliseFloat(float $value): string
    {
        if (is_nan($value)) {
            return 'd:fNaN';
        }

        if ($value === 0.0) {
            // `fdiv` rather than `/`: division by zero is a fatal error in PHP 8, so
            // `1 / 0.0` never returns. `fdiv` is the IEEE function for exactly this — it
            // yields -INF for -0.0 and +INF for 0.0.
            return fdiv(1.0, $value) === -INF ? 'd:f-0' : 'd:f0';
        }

        if (is_infinite($value)) {
            return $value > 0 ? 'd:fInf' : 'd:f-Inf';
        }

        return 'd:f'.sprintf('%.17G', $value);
    }

    /**
     * The canonical form of a whole claim set, ready to hash.
     *
     * @param  array<string, mixed>  $claims
     */
    public static function claims(array $claims): string
    {
        return self::canonicalise($claims);
    }

    /**
     * SHA-256 of the canonical form, hex.
     *
     * @param  array<string, mixed>  $claims
     */
    public static function digest(array $claims): string
    {
        return hash('sha256', self::claims($claims));
    }
}

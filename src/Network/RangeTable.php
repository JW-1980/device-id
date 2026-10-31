<?php

declare(strict_types=1);

namespace DeviceId\Network;

/**
 * A sorted, non-overlapping table of address ranges with a fixed-width value, built into
 * shards small enough to live in a key-value cache and searched with a binary search.
 *
 * ## Why shards
 *
 * A request must answer from the cache without unserialising the whole table: the ASN file
 * has some 700,000 ranges. IPv4 is split by its first octet (256 shards, about 10-50 KB each),
 * IPv6 by its first 12 bits (at most 4,096). A lookup reads one shard, a range that crosses a
 * shard boundary is cut at it, and the shard stores the addresses without their first byte.
 *
 * ## Record layout (per shard, ascending by start)
 *
 * `start` and `end` (4 or 16 bytes minus the stripped first byte) followed by `valueLength`
 * bytes of value. Everything is binary-comparable big-endian, so `strcmp` orders it.
 */
final class RangeTable
{
    public const V4 = 4;

    public const V6 = 16;

    /**
     * The shard id of a packed address: `4:<octet>` or `6:<3 hex digits>`.
     */
    public static function shardOf(string $packed): string
    {
        return strlen($packed) === self::V4
            ? '4:'.ord($packed[0])
            : '6:'.sprintf('%02x%x', ord($packed[0]), ord($packed[1]) >> 4);
    }

    /**
     * The first and last packed address of a shard.
     *
     * @return array{0: string, 1: string}
     */
    private static function bounds(string $shard): array
    {
        if (str_starts_with($shard, '4:')) {
            $octet = chr((int) substr($shard, 2));

            return [$octet."\x00\x00\x00", $octet."\xff\xff\xff"];
        }
        $hex = substr($shard, 2);
        $first = chr((int) hexdec(substr($hex, 0, 2)));
        $high = ((int) hexdec($hex[2])) << 4;

        return [$first.chr($high).str_repeat("\x00", 14), $first.chr($high | 0x0F).str_repeat("\xff", 14)];
    }

    /**
     * Append one range to the shard buffers, cutting it at shard boundaries.
     *
     * @param  array<string, string>  $buffers  shard id => records, appended to
     * @param  string  $start  packed address
     * @param  string  $end  packed address of the same family, not below $start
     * @param  string  $value  exactly the table's value length
     */
    public static function add(array &$buffers, string $start, string $end, string $value): void
    {
        $length = strlen($start);
        if (($length !== self::V4 && $length !== self::V6) || strlen($end) !== $length || strcmp($start, $end) > 0) {
            return;
        }

        $cursor = $start;
        while (true) {
            $shard = self::shardOf($cursor);
            [, $shardEnd] = self::bounds($shard);
            $pieceEnd = strcmp($end, $shardEnd) < 0 ? $end : $shardEnd;
            if (! isset($buffers[$shard])) {
                $buffers[$shard] = '';
            }
            $buffers[$shard] .= substr($cursor, 1).substr($pieceEnd, 1).$value;
            if ($pieceEnd === $end) {
                return;
            }
            $cursor = self::successor($pieceEnd);
            if ($cursor === null) {
                return;
            }
        }
    }

    /**
     * The value of the range containing a packed address in a shard, or null.
     */
    public static function find(string $shardData, string $packed, int $valueLength): ?string
    {
        $key = substr($packed, 1);
        $keyLength = strlen($key);
        $record = 2 * $keyLength + $valueLength;
        $count = intdiv(strlen($shardData), $record);

        $low = 0;
        $high = $count - 1;
        $found = -1;
        while ($low <= $high) {
            $mid = ($low + $high) >> 1;
            if (strcmp(substr($shardData, $mid * $record, $keyLength), $key) <= 0) {
                $found = $mid;
                $low = $mid + 1;
            } else {
                $high = $mid - 1;
            }
        }
        if ($found < 0) {
            return null;
        }

        $offset = $found * $record;
        if (strcmp($key, substr($shardData, $offset + $keyLength, $keyLength)) > 0) {
            return null;
        }

        return substr($shardData, $offset + 2 * $keyLength, $valueLength);
    }

    /**
     * The packed address after $address, or null at the top of the space.
     */
    private static function successor(string $address): ?string
    {
        for ($i = strlen($address) - 1; $i >= 0; $i--) {
            if ($address[$i] !== "\xff") {
                return substr($address, 0, $i).chr(ord($address[$i]) + 1).str_repeat("\x00", strlen($address) - $i - 1);
            }
        }

        return null;
    }
}

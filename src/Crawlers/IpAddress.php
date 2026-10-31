<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Crawlers;

/**
 * IPv4 and IPv6 address and CIDR handling on the packed binary form.
 *
 * One implementation serves both families, so an IPv4 address is never compared with an IPv6 prefix
 * by accident. An IPv4-mapped IPv6 address (`::ffff:192.0.2.1`, what a dual-stack socket reports for
 * an IPv4 client) is folded onto its IPv4 form first, so a client is not invisible to an IPv4 range
 * just because of the socket it arrived on.
 *
 * A prefix length of 0 is refused everywhere: a "/0" matches every address, so a typo in an
 * operator list or a corrupted vendor feed would otherwise allowlist the whole internet.
 */
final class IpAddress
{
    /**
     * The packed form of an address (4 or 16 bytes), IPv4-mapped IPv6 folded to 4 bytes, or null.
     */
    public static function pack(string $ip): ?string
    {
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }

        return self::fold($packed);
    }

    public static function same(string $a, string $b): bool
    {
        $packedA = self::pack($a);

        return $packedA !== null && $packedA === self::pack($b);
    }

    /**
     * An address or CIDR as [packed network, prefix bits], or null when it is not valid.
     * A bare address is a host prefix (/32, /128). The prefix is not masked: callers compare
     * only the first `bits` bits.
     *
     * @return array{0: string, 1: int}|null
     */
    public static function parseCidr(string $entry): ?array
    {
        $entry = trim($entry);
        if ($entry === '') {
            return null;
        }

        if (! str_contains($entry, '/')) {
            $packed = self::pack($entry);

            return $packed === null ? null : [$packed, strlen($packed) * 8];
        }

        [$address, $bits] = explode('/', $entry, 2);
        if (! ctype_digit($bits) || filter_var($address, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $raw = @inet_pton($address);
        if ($raw === false) {
            return null;
        }

        $length = (int) $bits;
        if ($length < 1 || $length > strlen($raw) * 8) {
            return null;
        }

        $packed = self::fold($raw);
        if (strlen($packed) !== strlen($raw)) {
            // ::ffff:a.b.c.d/N is the IPv4 prefix a.b.c.d/(N-96); anything shorter than /96 would
            // cover more than the mapped block and is refused rather than guessed at.
            $length -= 96;
            if ($length < 1) {
                return null;
            }
        }

        return [$packed, $length];
    }

    public static function isCidr(string $entry): bool
    {
        return self::parseCidr($entry) !== null;
    }

    /**
     * The canonical text of a valid entry (`192.0.2.0/24`), or null.
     */
    public static function normalise(string $entry): ?string
    {
        $parsed = self::parseCidr($entry);
        if ($parsed === null) {
            return null;
        }

        $text = @inet_ntop($parsed[0]);

        return $text === false ? null : $text.'/'.$parsed[1];
    }

    public static function inCidr(string $ip, string $cidr): bool
    {
        $packedIp = self::pack($ip);
        $parsed = self::parseCidr($cidr);

        return $packedIp !== null && $parsed !== null && self::packedInCidr($packedIp, $parsed[0], $parsed[1]);
    }

    public static function packedInCidr(string $packedIp, string $packedNetwork, int $bits): bool
    {
        if (strlen($packedIp) !== strlen($packedNetwork)) {
            return false;
        }

        $whole = intdiv($bits, 8);
        $remaining = $bits % 8;

        if ($whole > 0 && strncmp($packedIp, $packedNetwork, $whole) !== 0) {
            return false;
        }

        if ($remaining === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remaining)) & 0xFF;

        return (ord($packedIp[$whole]) & $mask) === (ord($packedNetwork[$whole]) & $mask);
    }

    private static function fold(string $packed): string
    {
        if (strlen($packed) === 16 && str_starts_with($packed, str_repeat("\0", 10)."\xff\xff")) {
            return substr($packed, 12);
        }

        return $packed;
    }
}

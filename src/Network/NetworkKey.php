<?php

declare(strict_types=1);

namespace DeviceId\Network;

use DeviceId\Crawlers\IpAddress;

/**
 * The network an address belongs to, at the granularity a host should count it.
 *
 * ## Two granularities, for two jobs
 *
 * - {@see endSite()}: IPv4 /32, IPv6 /56. One customer site: RIPE-690 recommends that ISPs give each
 *   end site a /48 or a /56, and many residential ISPs give a /56, so a /56 is the smallest IPv6 unit
 *   that is one household rather than one device. Use it where one household should count once
 *   (one guest vote per item per household) and neighbours must not collide.
 * - {@see forLimits()}: IPv4 /32, IPv6 /48. The largest block one party routinely controls: business
 *   end sites get a /48, and free tunnel brokers route a /48 to anyone who asks, which held 256 /56
 *   "households" and so 256 counted guest votes per duel (skeptical review M2). Use it for AGGREGATE
 *   caps (at most N guest votes per item per /48, a rate limit per /48), never for one-per-household
 *   dedupe: one residential ISP /48 holds up to 256 neighbouring /56 customers, so "one vote per /48"
 *   would silently drop honest neighbours.
 *
 * A host should apply both: dedupe by `endSite()`, cap by `forLimits()` with a small N (the cap is
 * the host's policy). IPv4 stays one address in both: one IPv4 address is already one household or
 * one carrier NAT, and widening it to a /24 would merge unrelated subscribers.
 *
 * The returned strings are canonical (`v6:2001:db8:1::/48`, IPv4-mapped IPv6 folded to IPv4) and
 * contain the prefix itself; store {@see keyed()} instead where the network must not be readable.
 */
final class NetworkKey
{
    public const IPV4_BITS = 32;

    public const IPV6_END_SITE_BITS = 56;

    public const IPV6_LIMIT_BITS = 48;

    /** The shortest secret {@see keyed()} accepts (the same floor as the device-key secret). */
    private const MIN_SECRET_LENGTH = 32;

    /**
     * IPv4 /32, IPv6 /48: for aggregate limits. Null for anything that is not an IP address.
     */
    public static function forLimits(string $ip): ?string
    {
        return self::prefix($ip, self::IPV4_BITS, self::IPV6_LIMIT_BITS);
    }

    /**
     * IPv4 /32, IPv6 /56: one end site, for one-per-household dedupe. Null for anything that is not
     * an IP address.
     */
    public static function endSite(string $ip): ?string
    {
        return self::prefix($ip, self::IPV4_BITS, self::IPV6_END_SITE_BITS);
    }

    /**
     * HMAC-SHA256 of {@see forLimits()} under the host's secret, or null for an invalid address or a
     * secret shorter than 32 bytes (never an unkeyed hash).
     */
    public static function keyed(string $ip, string $secret, bool $endSite = false): ?string
    {
        $prefix = $endSite ? self::endSite($ip) : self::forLimits($ip);
        if ($prefix === null || strlen($secret) < self::MIN_SECRET_LENGTH) {
            return null;
        }

        return hash_hmac('sha256', 'network:'.$prefix, $secret);
    }

    /**
     * The canonical masked prefix of an address, or null.
     */
    public static function prefix(string $ip, int $ipv4Bits, int $ipv6Bits): ?string
    {
        $packed = IpAddress::pack(trim($ip));
        if ($packed === null) {
            return null;
        }

        $v4 = strlen($packed) === 4;
        $bits = max(1, min($v4 ? 32 : 128, $v4 ? $ipv4Bits : $ipv6Bits));
        $masked = '';
        foreach (str_split($packed) as $index => $byte) {
            $keep = max(0, min(8, $bits - $index * 8));
            $masked .= chr(ord($byte) & ((0xFF << (8 - $keep)) & 0xFF));
        }

        return ($v4 ? 'v4:' : 'v6:').inet_ntop($masked).'/'.$bits;
    }
}

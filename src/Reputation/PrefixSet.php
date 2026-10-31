<?php

declare(strict_types=1);

namespace DeviceId\Reputation;

use DeviceId\Crawlers\IpAddress;

/**
 * A set of CIDR prefixes with a lookup that costs one hash probe per distinct prefix length
 * (at most 32 + 128), not one comparison per prefix: an AWS list has ten thousand entries.
 */
final class PrefixSet
{
    /** @var array<string, array<string, true>> `<bytes>/<bits>` => masked network => true */
    private array $byLength = [];

    /**
     * @param  list<string>  $cidrs
     */
    public function __construct(array $cidrs)
    {
        foreach ($cidrs as $cidr) {
            $parsed = IpAddress::parseCidr($cidr);
            if ($parsed !== null) {
                $this->byLength[strlen($parsed[0]).'/'.$parsed[1]][self::mask($parsed[0], $parsed[1])] = true;
            }
        }
    }

    public function contains(string $ip): bool
    {
        $packed = IpAddress::pack($ip);
        if ($packed === null) {
            return false;
        }

        foreach ($this->byLength as $key => $networks) {
            [$bytes, $bits] = explode('/', $key);
            if ((int) $bytes === strlen($packed) && isset($networks[self::mask($packed, (int) $bits)])) {
                return true;
            }
        }

        return false;
    }

    private static function mask(string $packed, int $bits): string
    {
        $whole = intdiv($bits, 8);
        $rest = $bits % 8;
        $out = substr($packed, 0, $whole);
        if ($rest > 0) {
            $out .= chr(ord($packed[$whole]) & ((0xFF << (8 - $rest)) & 0xFF));
        }

        return $out;
    }
}

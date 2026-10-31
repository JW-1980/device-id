<?php

declare(strict_types=1);

namespace DeviceId\Crawlers;

/**
 * Pure-PHP DNS adapter: `gethostbyaddr()` for the PTR name, `gethostbynamel()` plus
 * `dns_get_record(AAAA)` for the forward set.
 *
 * Safe for what it is used for, with one caveat that is the host's to honour: these calls use the
 * system resolver and have no timeout of their own, so call the verifier from a queue worker or
 * after the response, never while a visitor waits.
 *
 * `gethostbyaddr()` returns its input unchanged when the lookup fails, which is
 * indistinguishable from success except by comparing with the input; that case is "no answer".
 */
final class NativeDnsResolver implements DnsResolver
{
    public function reverse(string $ip): ?string
    {
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $host = @gethostbyaddr($ip);
        if ($host === false || $host === $ip || $host === '') {
            return null;
        }

        return rtrim($host, '.');
    }

    public function forward(string $hostname): array
    {
        if ($hostname === '') {
            return [];
        }

        $addresses = [];

        $v4 = @gethostbynamel($hostname);
        if ($v4 !== false) {
            foreach ($v4 as $address) {
                if ($address !== '') {
                    $addresses[$address] = true;
                }
            }
        }

        $records = @dns_get_record($hostname, DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $record) {
                $address = $record['ipv6'] ?? null;
                if (is_string($address) && $address !== '') {
                    $addresses[$address] = true;
                }
            }
        }

        return array_map('strval', array_keys($addresses));
    }
}

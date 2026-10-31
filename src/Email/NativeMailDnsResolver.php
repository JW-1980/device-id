<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * A {@see MailDnsResolver} over PHP's own `dns_get_record()`, for hosts with nothing better.
 *
 * `dns_get_record()` cannot tell "the name does not exist" from "the lookup failed" (both are
 * `false`). So an answer of "no mail" is only given when ALL of these hold: MX, A and AAAA
 * lookups all returned nothing, and a control lookup of a name that always exists succeeded in the
 * same call (the resolver is working). Even then {@see DomainMailCheck} needs a second, later
 * confirmation before it reports `no_mail`. A null MX (RFC 7505) is recognised directly. Anything
 * else is `unknown`.
 */
final class NativeMailDnsResolver implements MailDnsResolver
{
    public function __construct(private readonly string $controlDomain = 'example.com') {}

    public function mailStatus(string $domain): string
    {
        if (! function_exists('dns_get_record')) {
            return self::UNKNOWN;
        }
        try {
            $mx = @dns_get_record($domain, DNS_MX);
            if (is_array($mx) && $mx !== []) {
                foreach ($mx as $record) {
                    $target = is_array($record) ? (string) ($record['target'] ?? '') : '';
                    if ($target !== '' && $target !== '.') {
                        return self::MAIL_OK;
                    }
                }

                return self::NO_MAIL; // only null MX records (RFC 7505)
            }
            foreach ([DNS_A, DNS_AAAA] as $type) {
                $records = @dns_get_record($domain, $type);
                if (is_array($records) && $records !== []) {
                    return self::MAIL_OK;
                }
            }
            $control = @dns_get_record($this->controlDomain, DNS_A);

            return is_array($control) && $control !== [] ? self::NO_MAIL : self::UNKNOWN;
        } catch (\Throwable) {
            return self::UNKNOWN;
        }
    }
}

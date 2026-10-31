<?php

declare(strict_types=1);

namespace DeviceId\Crawlers;

/**
 * Label-boundary suffix matching for reverse-DNS names.
 *
 * `crawl-1.googlebot.com` and `googlebot.com` match `googlebot.com`; `evil-googlebot.com` and
 * `googlebot.com.evil.net` do not.
 *
 * An entry with one `*` is a host pattern instead of a suffix: `rate-limited-proxy-*.google.com`
 * matches a name whose FIRST label starts with `rate-limited-proxy-` followed by at least one more
 * character, and whose remaining labels are exactly `google.com`. The wildcard never spans a dot.
 * Patterns are how a vendor domain that also serves non-crawler traffic (Google's `google.com`
 * holds both its special-case crawlers and its user-triggered proxies) is narrowed to the crawler
 * names the vendor documents.
 */
final class HostnameSuffix
{
    /**
     * @param  list<string>  $suffixes
     */
    public static function matches(string $hostname, array $suffixes): bool
    {
        $host = strtolower(rtrim(trim($hostname), '.'));
        if ($host === '') {
            return false;
        }

        foreach ($suffixes as $suffix) {
            $suffix = strtolower(trim($suffix, ". \t"));
            if ($suffix === '') {
                continue;
            }
            if (str_contains($suffix, '*')) {
                if (self::matchesPattern($host, $suffix)) {
                    return true;
                }

                continue;
            }
            if ($host === $suffix || str_ends_with($host, '.'.$suffix)) {
                return true;
            }
        }

        return false;
    }

    private static function matchesPattern(string $host, string $pattern): bool
    {
        $parts = explode('*', $pattern);
        if (count($parts) !== 2 || str_contains($parts[0], '.') || ! str_starts_with($parts[1], '.') || strlen($parts[1]) < 2) {
            return false;
        }

        [$labelPrefix, $domain] = $parts;
        if (! str_ends_with($host, $domain)) {
            return false;
        }

        $label = substr($host, 0, strlen($host) - strlen($domain));

        return strlen($label) > strlen($labelPrefix)
            && str_starts_with($label, $labelPrefix)
            && ! str_contains($label, '.');
    }
}

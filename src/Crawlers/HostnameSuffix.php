<?php

declare(strict_types=1);

namespace DeviceId\Crawlers;

/**
 * Label-boundary suffix matching for reverse-DNS names.
 *
 * `crawl-1.googlebot.com` and `googlebot.com` match `googlebot.com`; `evil-googlebot.com` and
 * `googlebot.com.evil.net` do not.
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
            if ($host === $suffix || str_ends_with($host, '.'.$suffix)) {
                return true;
            }
        }

        return false;
    }
}

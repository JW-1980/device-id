<?php

declare(strict_types=1);

namespace DeviceId\Reputation;

use DeviceId\Crawlers\IpAddress;

/**
 * Turns a feed body into canonical CIDR strings. Anything that is not a valid prefix is
 * dropped, and a prefix of /0 is refused by {@see IpAddress::parseCidr()} (a typo or a corrupted
 * feed must not flag the whole internet). A body that yields nothing is `null`, never an empty
 * list: an empty parse is a broken fetch, not a clean feed.
 */
final class FeedParser
{
    /** A feed larger than this many prefixes is refused as implausible. */
    public const MAX_PREFIXES = 200000;

    /**
     * @return list<string>|null
     */
    public static function parse(string $format, string $body): ?array
    {
        $candidates = match ($format) {
            FeedDefinition::FORMAT_IP_LINES, FeedDefinition::FORMAT_CIDR_LINES => self::lines($body),
            FeedDefinition::FORMAT_NDJSON_CIDR => self::ndjson($body),
            FeedDefinition::FORMAT_CSV_FIRST_COLUMN => self::csvFirstColumn($body),
            FeedDefinition::FORMAT_TORDNSEL_DIRECTORY => self::exitAddresses($body),
            FeedDefinition::FORMAT_AWS => self::json($body, static fn (array $d): array => [
                ...array_column(is_array($d['prefixes'] ?? null) ? $d['prefixes'] : [], 'ip_prefix'),
                ...array_column(is_array($d['ipv6_prefixes'] ?? null) ? $d['ipv6_prefixes'] : [], 'ipv6_prefix'),
            ]),
            FeedDefinition::FORMAT_GCP => self::json($body, static function (array $d): array {
                $out = [];
                foreach (is_array($d['prefixes'] ?? null) ? $d['prefixes'] : [] as $p) {
                    $out[] = $p['ipv4Prefix'] ?? $p['ipv6Prefix'] ?? null;
                }

                return $out;
            }),
            FeedDefinition::FORMAT_ORACLE => self::json($body, static function (array $d): array {
                $out = [];
                foreach (is_array($d['regions'] ?? null) ? $d['regions'] : [] as $region) {
                    foreach (is_array($region['cidrs'] ?? null) ? $region['cidrs'] : [] as $cidr) {
                        $out[] = $cidr['cidr'] ?? null;
                    }
                }

                return $out;
            }),
            default => [],
        };

        $prefixes = [];
        foreach ($candidates as $candidate) {
            if (is_string($candidate)) {
                $normal = IpAddress::normalise($candidate);
                if ($normal !== null) {
                    $prefixes[$normal] = true;
                }
            }
        }
        if ($prefixes === [] || count($prefixes) > self::MAX_PREFIXES) {
            return null;
        }

        return array_keys($prefixes);
    }

    /**
     * The newest file name in a CollecTor exit-list directory index (`YYYY-MM-DD-HH-MM-SS`; the
     * names sort in time order), or null when the page lists none.
     */
    public static function newestExitListName(string $index): ?string
    {
        if (preg_match_all('/href="(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})"/', $index, $m) < 1) {
            return null;
        }
        $names = $m[1];
        sort($names, SORT_STRING);

        return $names[count($names) - 1];
    }

    /**
     * `ExitAddress <ip> <date> <time>` lines of a tordnsel exit list.
     *
     * @return list<string>
     */
    private static function exitAddresses(string $body): array
    {
        $out = [];
        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            if (preg_match('/^ExitAddress\s+(\S+)\s/', $line, $m) === 1) {
                $out[] = $m[1];
            }
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private static function lines(string $body): array
    {
        $out = [];
        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            $line = trim(explode(';', explode('#', $line, 2)[0], 2)[0]);
            if ($line !== '') {
                $out[] = $line;
            }
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private static function ndjson(string $body): array
    {
        $out = [];
        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            $row = json_decode(trim($line), true);
            if (is_array($row) && is_string($row['cidr'] ?? null)) {
                $out[] = $row['cidr'];
            }
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private static function csvFirstColumn(string $body): array
    {
        $out = [];
        foreach (self::lines($body) as $line) {
            $out[] = trim(explode(',', $line, 2)[0]);
        }

        return $out;
    }

    /**
     * @param  callable(array<array-key, mixed>): array<array-key, mixed>  $extract
     * @return list<mixed>
     */
    private static function json(string $body, callable $extract): array
    {
        $data = json_decode($body, true);

        return is_array($data) ? array_values($extract($data)) : [];
    }
}

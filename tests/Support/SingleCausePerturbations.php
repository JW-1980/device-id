<?php

declare(strict_types=1);

namespace DeviceId\Tests\Support;

/**
 * Single root-cause perturbations of a capture record (`tools/capture` dataset shape).
 *
 * Each entry changes ONE real-world cause, everywhere that cause shows up, and nothing else: a
 * User-Agent switcher rewrites the header and (depending on the tool) navigator.userAgent,
 * appVersion and the worker's userAgent together; a browser language setting moves
 * navigator.languages and Accept-Language together; a proxy rewrites headers only. A perturbation
 * that would need values this harness cannot reproduce faithfully (a time-zone change also moves
 * the historic LMT offsets the engine reads) is not synthesised here; those causes are covered by
 * real captures instead (`tests/Fixtures/fingerprint/single-cause/`).
 *
 * The invariant they serve (`SingleRootCauseInvariantTest`): no single root cause may move an
 * honest browser into `block`, and none may add more than one evidence group's weight.
 */
final class SingleCausePerturbations
{
    private const UA_FIREFOX_LINUX = 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0';

    private const UA_SAFARI_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15';

    private const UA_CHROME_ANDROID = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/537.36';

    private const UA_CHROME_WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36';

    private const UA_EDGE_WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 Edg/%d.0.0.0';

    private const UA_CHROME_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36';

    /**
     * name => fn(record): ?record (null when the cause does not apply to this record)
     *
     * @return array<string, \Closure(array<string, mixed>): ?array<string, mixed>>
     */
    public static function all(): array
    {
        $out = [];
        foreach (['everywhere' => ['header', 'page', 'worker'], 'header_only' => ['header'], 'page_only' => ['page'], 'page_and_worker' => ['page', 'worker']] as $scope => $where) {
            $out["ua_older_major_{$scope}"] = static fn (array $r): ?array => self::withUa($r, $where, static fn (string $ua): ?string => self::shiftMajor($ua, -14));
            $out["ua_newer_major_{$scope}"] = static fn (array $r): ?array => self::withUa($r, $where, static fn (string $ua): ?string => self::shiftMajor($ua, +4));
            $out["ua_firefox_{$scope}"] = static fn (array $r): ?array => self::withUa($r, $where, static fn (string $ua): ?string => str_contains($ua, 'Firefox/') ? null : self::UA_FIREFOX_LINUX);
            $out["ua_safari_mac_{$scope}"] = static fn (array $r): ?array => self::withUa($r, $where, static fn (string $ua): ?string => str_contains($ua, 'Version/') && ! str_contains($ua, 'Chrome/') ? null : self::UA_SAFARI_MAC);
            $out["ua_chrome_windows_{$scope}"] = static fn (array $r): ?array => self::withUa($r, $where, static fn (string $ua): ?string => sprintf(self::UA_CHROME_WINDOWS, self::major($ua) ?? 140));
            $out["ua_chrome_mac_{$scope}"] = static fn (array $r): ?array => self::withUa($r, $where, static fn (string $ua): ?string => sprintf(self::UA_CHROME_MAC, self::major($ua) ?? 140));
            $out["ua_edge_windows_{$scope}"] = static fn (array $r): ?array => self::withUa($r, $where, static fn (string $ua): ?string => sprintf(self::UA_EDGE_WINDOWS, self::major($ua) ?? 140, self::major($ua) ?? 140));
            $out["ua_chrome_android_{$scope}"] = static fn (array $r): ?array => self::withUa($r, $where, static fn (string $ua): ?string => sprintf(self::UA_CHROME_ANDROID, self::major($ua) ?? 140));
        }

        // A browser language setting: navigator.language(s), the worker's and Accept-Language move together.
        $out['language_setting_japanese'] = static fn (array $r): ?array => self::withLanguage($r, ['ja-JP', 'ja'], true);
        // A proxy or extension that rewrites Accept-Language only.
        $out['accept_language_rewritten'] = static fn (array $r): ?array => self::withHeader($r, 'accept-language', 'de-DE,de;q=0.9');
        // A proxy or privacy extension that strips every Client-Hints header.
        $out['client_hints_headers_stripped'] = static fn (array $r): ?array => self::withoutHeaders($r, static fn (string $name): bool => str_starts_with($name, 'sec-ch-'));
        // A proxy that strips the Sec-Fetch-* metadata headers.
        $out['sec_fetch_headers_stripped'] = static fn (array $r): ?array => self::withoutHeaders($r, static fn (string $name): bool => str_starts_with($name, 'sec-fetch-'));

        return $out;
    }

    /**
     * @param  array<string, mixed>  $record
     * @param  list<string>  $where  header | page | worker
     * @param  \Closure(string): ?string  $rewrite
     * @return array<string, mixed>|null
     */
    public static function withUa(array $record, array $where, \Closure $rewrite): ?array
    {
        $identity = $record['claims']['tier1']['tier1']['environment']['identity'] ?? null;
        $current = is_array($identity) && is_string($identity['userAgent'] ?? null) ? $identity['userAgent'] : null;
        if ($current === null) {
            return null;
        }
        $new = $rewrite($current);
        if ($new === null || $new === $current) {
            return null;
        }

        if (in_array('page', $where, true)) {
            $record['claims']['tier1']['tier1']['environment']['identity']['userAgent'] = $new;
            $record['claims']['tier1']['tier1']['environment']['identity']['appVersion'] = substr($new, strlen('Mozilla/'));
            if (isset($record['claims']['tier2']['tier2']['workerScope']['window']['userAgent'])) {
                $record['claims']['tier2']['tier2']['workerScope']['window']['userAgent'] = $new;
            }
        }
        if (in_array('worker', $where, true) && isset($record['claims']['tier2']['tier2']['workerScope']['worker']['userAgent'])) {
            $record['claims']['tier2']['tier2']['workerScope']['worker']['userAgent'] = $new;
        }
        if (in_array('header', $where, true)) {
            $record = self::withHeader($record, 'user-agent', $new) ?? $record;
        }

        return $record;
    }

    /**
     * @param  array<string, mixed>  $record
     * @param  list<string>  $languages
     * @return array<string, mixed>|null
     */
    private static function withLanguage(array $record, array $languages, bool $header): ?array
    {
        if (! isset($record['claims']['tier1']['tier1']['environment']['identity'])) {
            return null;
        }
        $record['claims']['tier1']['tier1']['environment']['identity']['language'] = $languages[0];
        $record['claims']['tier1']['tier1']['environment']['identity']['languages'] = $languages;
        foreach (['window', 'worker'] as $scope) {
            if (isset($record['claims']['tier2']['tier2']['workerScope'][$scope]['language'])) {
                $record['claims']['tier2']['tier2']['workerScope'][$scope]['language'] = $languages[0];
                $record['claims']['tier2']['tier2']['workerScope'][$scope]['languages'] = implode(',', $languages);
            }
        }

        return $header ? self::withHeader($record, 'accept-language', $languages[0].','.$languages[1].';q=0.9') : $record;
    }

    /**
     * @param  array<string, mixed>  $record
     * @return array<string, mixed>|null
     */
    private static function withHeader(array $record, string $name, string $value): ?array
    {
        $changed = false;
        foreach (['claims_request_headers', 'navigation_headers'] as $list) {
            foreach ($record['transport'][$list] ?? [] as $i => $pair) {
                if (strtolower((string) $pair[0]) === $name) {
                    $record['transport'][$list][$i][1] = $value;
                    $changed = true;
                }
            }
        }

        return $changed ? $record : null;
    }

    /**
     * @param  array<string, mixed>  $record
     * @param  \Closure(string): bool  $drop
     * @return array<string, mixed>|null
     */
    private static function withoutHeaders(array $record, \Closure $drop): ?array
    {
        $changed = false;
        foreach (['claims_request_headers', 'navigation_headers'] as $list) {
            $kept = [];
            foreach ($record['transport'][$list] ?? [] as $pair) {
                if ($drop(strtolower((string) $pair[0]))) {
                    $changed = true;

                    continue;
                }
                $kept[] = $pair;
            }
            $record['transport'][$list] = $kept;
        }

        return $changed ? $record : null;
    }

    private static function major(string $ua): ?int
    {
        return preg_match('/(?:Chrome|Firefox|Version)\/(\d+)/', $ua, $m) === 1 ? (int) $m[1] : null;
    }

    private static function shiftMajor(string $ua, int $by): ?string
    {
        $out = preg_replace_callback('/((?:Chrome|Firefox|Version|rv:)\/?)(\d+)/', static fn (array $m): string => $m[1].max(1, (int) $m[2] + $by), $ua);

        return is_string($out) ? $out : null;
    }
}

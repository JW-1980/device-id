<?php

declare(strict_types=1);

/**
 * Refresh (and inspect) the local network data from a command line, for a host with no
 * scheduler integration of its own and for trying the data out.
 *
 *   php tools/network/refresh.php --cache-dir=/var/cache/device-id            refresh what is stale
 *   php tools/network/refresh.php --cache-dir=/var/cache/device-id --lookup=8.8.8.8
 *
 * The transport policy a host's own fetcher should copy: HTTPS only, no redirects followed, a
 * 64 MB body cap, a 60 second timeout. The cache is one file per key (a plain `CrawlerCache`);
 * a host with Redis or Laravel's cache writes the same few lines against its own store.
 * Needs ext-curl and ext-zlib, and about 200 MB of memory (`php -d memory_limit=512M`).
 */
require __DIR__.'/../../src/autoload.php';

use DeviceId\Crawlers\CrawlerCache;
use DeviceId\Crawlers\RangeFetcher;
use DeviceId\Network\NetworkDatabase;

$options = [];
foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $arg, $m) === 1) {
        $options[$m[1]] = $m[2] ?? 'true';
    }
}
$directory = $options['cache-dir'] ?? null;
if (! is_string($directory) || $directory === '') {
    fwrite(STDERR, "usage: php tools/network/refresh.php --cache-dir=DIR [--lookup=IP]\n");
    exit(2);
}
if (! is_dir($directory) && ! mkdir($directory, 0700, true) && ! is_dir($directory)) {
    fwrite(STDERR, "cannot create {$directory}\n");
    exit(2);
}

$cache = new class($directory) implements CrawlerCache
{
    public function __construct(private string $directory) {}

    private function path(string $key): string
    {
        return $this->directory.'/'.hash('sha256', $key).'.json';
    }

    public function get(string $key): ?array
    {
        $raw = @file_get_contents($this->path($key));
        $entry = $raw === false ? null : json_decode($raw, true);
        if (! is_array($entry) || ! is_int($entry['expires'] ?? null) || $entry['expires'] <= time()) {
            return null;
        }

        return is_array($entry['value'] ?? null) ? $entry['value'] : null;
    }

    public function put(string $key, array $value, int $ttlSeconds): void
    {
        $temporary = $this->path($key).'.'.bin2hex(random_bytes(4)).'.tmp';
        if (@file_put_contents($temporary, json_encode(['expires' => time() + max(1, $ttlSeconds), 'value' => $value])) !== false) {
            @rename($temporary, $this->path($key));
        }
    }

    public function add(string $key, array $value, int $ttlSeconds): bool
    {
        if ($this->get($key) !== null) {
            return false;
        }
        $this->put($key, $value, $ttlSeconds);

        return true;
    }

    public function forget(string $key): void
    {
        @unlink($this->path($key));
    }
};

$fetcher = new class implements RangeFetcher
{
    public function fetch(string $url): ?string
    {
        if (! str_starts_with($url, 'https://') || ! function_exists('curl_init')) {
            return null;
        }
        $curl = curl_init($url);
        $received = 0;
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_USERAGENT => 'device-id-network-refresh',
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => static function ($handle, $total, $downloaded) use (&$received): int {
                $received = (int) $downloaded;

                return $received > 67108864 ? 1 : 0;
            },
        ]);
        $body = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);

        return is_string($body) && $status >= 200 && $status < 300 ? $body : null;
    }
};

$database = NetworkDatabase::withDefaults($fetcher, $cache);

if (isset($options['lookup'])) {
    $facts = $database->lookup($options['lookup']);
    echo json_encode(['state' => $facts->state, 'country' => $facts->country, 'asn' => $facts->asn, 'category' => $facts->asnCategory, 'unusable' => $facts->unusable], JSON_PRETTY_PRINT)."\n";
    exit(0);
}

$started = microtime(true);
$result = $database->refreshStale();
foreach ($result as $key => $state) {
    echo sprintf("%-14s %s\n", $key, $state);
}
echo sprintf("done in %.1fs, peak %d MB\n", microtime(true) - $started, memory_get_peak_usage(true) / 1048576);
echo "Attribution to display:\n  ".implode("\n  ", $database->attribution())."\n";
exit(in_array('failed', $result, true) ? 1 : 0);

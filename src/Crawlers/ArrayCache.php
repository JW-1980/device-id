<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Crawlers;

/**
 * An in-process cache with injectable time: for tests, the demo, and hosts with nothing better.
 * It does not outlive the PHP process, so under PHP-FPM it caches nothing between requests.
 */
final class ArrayCache implements CrawlerCache
{
    /** @var array<string, array{0: array<array-key, mixed>, 1: int}> */
    private array $items = [];

    /** @param  (\Closure(): int)|null  $clock */
    public function __construct(private ?\Closure $clock = null) {}

    public function get(string $key): ?array
    {
        $item = $this->items[$key] ?? null;
        if ($item === null) {
            return null;
        }
        if ($item[1] <= $this->currentTime()) {
            unset($this->items[$key]);

            return null;
        }

        return $item[0];
    }

    public function put(string $key, array $value, int $ttlSeconds): void
    {
        $this->items[$key] = [$value, $this->currentTime() + max(1, $ttlSeconds)];
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
        unset($this->items[$key]);
    }

    private function currentTime(): int
    {
        return $this->clock === null ? time() : ($this->clock)();
    }
}

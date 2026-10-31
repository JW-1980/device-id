<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Crawlers;

/**
 * The cache the host provides (any key-value store with a TTL).
 *
 * Values are plain arrays of scalars. Implementations must not throw; a store that is down
 * should behave as a miss (`get` null, `add` true), so verification degrades to "undecided",
 * never to "verified".
 */
interface CrawlerCache
{
    /**
     * @return array<array-key, mixed>|null
     */
    public function get(string $key): ?array;

    /**
     * @param  array<array-key, mixed>  $value
     */
    public function put(string $key, array $value, int $ttlSeconds): void;

    /**
     * Store only if the key is absent; true when this call stored it. Atomic where the store allows.
     *
     * @param  array<array-key, mixed>  $value
     */
    public function add(string $key, array $value, int $ttlSeconds): bool;

    public function forget(string $key): void;
}

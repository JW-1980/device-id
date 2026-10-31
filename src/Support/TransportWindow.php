<?php

declare(strict_types=1);

namespace DeviceId\Support;

/**
 * One identity's rolling counters, and the window they roll over on.
 *
 * A value object rather than an array so the shapes cannot drift: the cached
 * representation and the in-memory one are produced by the same two methods, and
 * PHPStan can check both.
 *
 * ## Why there is no `distinctPaths`
 *
 * The first version carried a `distinctPaths` list, appended to on every request,
 * capped at `antiscraping.signals.max_tracked_paths` (128), serialised into the
 * cache entry, and read by nothing. No check consumed it. It was up to 128 strings
 * per identity, held in the cache for the whole window and then written again on the
 * roll-over, in exchange for nothing — and it made `withDocument()` and
 * `withSubresource()` carry a `$maxTrackedPaths` parameter purely to service it.
 *
 * Removing it also changes the cached shape, so `CACHE_VERSION` in
 * `TransportIntegrityState` is bumped. A version bump is the cheap way to be wrong
 * here: without it, a stale entry carrying `distinct_paths` would be read by the
 * new code, and the failure would be a silently wrong counter rather than a loud one.
 */
final class TransportWindow
{
    public function __construct(
        public readonly int $firstSeenAt,
        public readonly int $now,
        public readonly int $documents,
        public readonly int $subresources,
    ) {}

    public static function empty(): self
    {
        return new self(time(), time(), 0, 0);
    }

    public static function starting(int $now, int $windowSeconds): self
    {
        return new self($now, $now, 0, 0);
    }

    /**
     * Subresources per document.
     *
     * Null when there is not yet a document to divide by, which is a normal
     * first-request state and must not be reported as a ratio of zero.
     */
    public function subresourceRatio(): ?float
    {
        if ($this->documents < 1) {
            return null;
        }

        return round($this->subresources / $this->documents, 2);
    }

    /**
     * One more document. The path is not recorded — see the class docblock.
     */
    public function withDocument(): self
    {
        return new self(
            $this->firstSeenAt,
            $this->now,
            $this->documents + 1,
            $this->subresources,
        );
    }

    /**
     * One more subresource. The path is not recorded — see the class docblock.
     */
    public function withSubresource(): self
    {
        return new self(
            $this->firstSeenAt,
            $this->now,
            $this->documents,
            $this->subresources + 1,
        );
    }

    /**
     * @return array{documents: int, subresources: int, first_seen_at: int}
     */
    public function toArray(): array
    {
        return [
            'documents' => $this->documents,
            'subresources' => $this->subresources,
            'first_seen_at' => $this->firstSeenAt,
        ];
    }
}

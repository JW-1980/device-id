<?php

declare(strict_types=1);

namespace DeviceId\Crawlers;

/**
 * The outcome of checking a "I am Googlebot" claim. Five states, kept distinct on purpose:
 * collapsing "DNS contradicted the claim" into "we could not ask DNS" would turn a resolver outage
 * into a mass de-ranking event, and collapsing "cannot be decided" into "verified" would hand an
 * exemption to anyone who can type a User-Agent.
 *
 * Only `verified` allows anything. Every failure mode (no DNS, exception, empty answer, cache
 * down, feed unreachable) lands on `unverifiable` or `pending`, never on `verified`.
 */
final class CrawlerVerification
{
    public const STATUS_NONE = 'none';

    public const STATUS_VERIFIED = 'verified';

    /** DNS (or the vendor's published list) answered and contradicts the claim. */
    public const STATUS_FORGED = 'forged';

    /** Not resolved yet; the host should resolve it in the background. */
    public const STATUS_PENDING = 'pending';

    /** Cannot be decided: no method for this vendor, or the lookup produced no answer. */
    public const STATUS_UNVERIFIABLE = 'unverifiable';

    /** Recorded in place of a hostname when the verdict came from a published list, not DNS. */
    public const RANGE_EVIDENCE = 'published-ip-range';

    private function __construct(
        public readonly string $status,
        public readonly ?string $crawler = null,
        public readonly ?string $hostname = null,
    ) {}

    public static function none(): self
    {
        return new self(self::STATUS_NONE);
    }

    public static function verified(string $crawler, string $hostname): self
    {
        return new self(self::STATUS_VERIFIED, $crawler, $hostname);
    }

    public static function forged(string $crawler, ?string $hostname = null): self
    {
        return new self(self::STATUS_FORGED, $crawler, $hostname);
    }

    public static function pending(string $crawler): self
    {
        return new self(self::STATUS_PENDING, $crawler);
    }

    public static function unverifiable(string $crawler): self
    {
        return new self(self::STATUS_UNVERIFIABLE, $crawler);
    }

    /**
     * @param  array<mixed, mixed>  $cached
     */
    public static function fromArray(array $cached): ?self
    {
        $status = $cached['status'] ?? null;
        $crawler = $cached['crawler'] ?? null;
        $hostname = $cached['hostname'] ?? null;

        if (! is_string($status) || ! in_array($status, self::statuses(), true)) {
            return null;
        }

        return new self($status, is_string($crawler) ? $crawler : null, is_string($hostname) ? $hostname : null);
    }

    /**
     * @return array<string, string|null>
     */
    public function toArray(): array
    {
        return ['status' => $this->status, 'crawler' => $this->crawler, 'hostname' => $this->hostname];
    }

    /**
     * @return list<string>
     */
    public static function statuses(): array
    {
        return [self::STATUS_NONE, self::STATUS_VERIFIED, self::STATUS_FORGED, self::STATUS_PENDING, self::STATUS_UNVERIFIABLE];
    }

    public function claimsCrawler(): bool
    {
        return $this->status !== self::STATUS_NONE && $this->crawler !== null;
    }

    public function isVerified(): bool
    {
        return $this->status === self::STATUS_VERIFIED;
    }

    public function isForged(): bool
    {
        return $this->status === self::STATUS_FORGED;
    }

    /** Neither an exemption nor a penalty. */
    public function isNeutral(): bool
    {
        return $this->status === self::STATUS_PENDING || $this->status === self::STATUS_UNVERIFIABLE;
    }
}

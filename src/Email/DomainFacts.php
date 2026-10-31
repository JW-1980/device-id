<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * What the local domain lists say about one mail domain. Each answer is `true` (listed), `false`
 * (the list answered and the domain is not on it) or `null` (no usable list: unknown, never
 * "clean"). Nothing here is a score.
 */
final readonly class DomainFacts
{
    public const STATE_OK = 'ok';

    public const STATE_PARTIAL = 'partial';

    public const STATE_UNAVAILABLE = 'unavailable';

    /**
     * @param  list<string>  $unusable  feeds that were stale, missing or not accepted
     */
    public function __construct(
        public string $state = self::STATE_UNAVAILABLE,
        public ?bool $disposable = null,
        public ?bool $free = null,
        public ?bool $forwarding = null,
        public array $unusable = [],
    ) {}

    public static function unknown(): self
    {
        return new self;
    }
}

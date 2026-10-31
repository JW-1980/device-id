<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * One e-mail-domain list download: where it is, how to read it, which categories it yields and
 * the licence finding that decides whether it may be used. Same licence statuses and the same
 * rule as the network feeds: a feed with an attribution text or the status
 * `public_credit_required` is never loaded.
 */
final readonly class DomainFeed
{
    /** One domain per line, `#` comments ignored. */
    public const FORMAT_LINES = 'lines';

    /** The disposable/static-disposable-lists `mailservices.json` (provider objects with `type`, `costs`, `hosts`). */
    public const FORMAT_MAILSERVICES = 'mailservices_json';

    public const DISPOSABLE = 'disposable';

    public const FREE = 'free';

    public const FORWARDING = 'forwarding';

    /**
     * @param  list<string>  $urls  tried in order
     * @param  list<string>  $categories  what the feed yields
     * @param  array{status: string, note: string, source: string, checked_on: string}  $licence
     */
    public function __construct(
        public string $key,
        public string $name,
        public array $urls,
        public string $format,
        public array $categories,
        public array $licence,
        /** Non-empty means the publisher demands a visible credit: the feed is then never loaded. */
        public string $attribution = '',
        public int $minimumRefreshSeconds = 43200,
        public int $freshSeconds = 172800,
        /** Older than this: ignored (a stale list is no evidence), never read as clean. */
        public int $maxAgeSeconds = 2592000,
    ) {}

    public function isUsableWithout(): bool
    {
        return $this->attribution === ''
            && in_array($this->licence['status'], ['permitted', 'permitted_with_notice'], true);
    }
}

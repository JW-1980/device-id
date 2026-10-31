<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * An e-mail address taken apart. It holds the raw parts, so it is for the request that already
 * has the address; it must never be stored, logged or put into a training row. What may be kept
 * is {@see EmailNormalizer::hash()} (keyed) or the bucketed {@see EmailAssessment}.
 */
final readonly class ParsedEmail
{
    /**
     * @param  string  $local  the local part as typed, lower-cased, tag included
     * @param  string  $domain  lower-cased, ASCII (punycode) when `ext-intl` is available, no trailing dot
     * @param  string  $mailbox  the local part without its `+tag` and, for providers that ignore them, without dots
     * @param  string|null  $tag  the `+tag` (sub-address) without the plus, or null
     * @param  string  $canonicalDomain  `gmail.com` for `googlemail.com`, otherwise the domain
     */
    public function __construct(
        public string $local,
        public string $domain,
        public string $mailbox,
        public ?string $tag,
        public string $canonicalDomain,
    ) {}

    /** The canonical address: one mailbox, one string. */
    public function canonical(): string
    {
        return $this->mailbox.'@'.$this->canonicalDomain;
    }
}

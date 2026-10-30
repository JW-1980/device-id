<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Transport;

/**
 * The outcome of looking for a JA4 on a request: a fingerprint, or a reason there is
 * none.
 *
 * Structurally the same shape as `RawHeaderOrder`, and for the same reason. Both are
 * values a TLS terminator supplies and neither can be computed in PHP, so both have to
 * answer "why not" in a way the log can use and the client never sees.
 */
final readonly class Ja4Capture
{
    private function __construct(
        public ?Ja4 $ja4,
        public ?string $reason,
    ) {}

    public static function captured(Ja4 $ja4): self
    {
        return new self($ja4, null);
    }

    public static function unavailable(string $reason): self
    {
        return new self(null, $reason);
    }

    public function ok(): bool
    {
        return $this->ja4 !== null;
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Envelope;

/**
 * The outcome of parsing a claims body: an envelope, or a named reason it was not
 * one.
 *
 * ## Why the reason is a value object and not a string return
 *
 * Two callers need this and they need different things. The log wants the reason, so
 * an operator can tell "the client is too old" from "somebody is probing". The
 * response wants *nothing* — a prober who learns which validation to work around
 * next has been told. So the reason travels on this object, is written to the log,
 * and is never rendered to the client.
 */
final readonly class EnvelopeParse
{
    private function __construct(
        public ?ClientClaimsEnvelope $envelope,
        public ?string $reason,
    ) {}

    public static function accepted(ClientClaimsEnvelope $envelope): self
    {
        return new self($envelope, null);
    }

    public static function rejected(string $reason): self
    {
        return new self(null, $reason);
    }

    public function ok(): bool
    {
        return $this->envelope !== null;
    }
}

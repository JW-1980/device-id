<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Support;

use NutriCompare\Fingerprint\Transport\TransportIntegrity;

/**
 * One thing observed about an HTTP request that the server can prove.
 *
 * WHY THIS IS A VALUE OBJECT AND NOT A STRING. A finding's `code` is the stable
 * identifier that gets stored, indexed, alerted on and rendered on the admin
 * screen; its `detail` is a human sentence and may be reworded at any time. Code
 * review therefore greps for the *code*, and the prose is free to improve. The
 * distinction matters because a "why was this blocked?" answer three months from
 * now has to be greppable, and prose is not.
 *
 * WHY `severity` HAS EXACTLY TWO VALUES. A `hard` finding is one no conforming
 * browser can produce - a request that violates its own protocol. A `soft` finding
 * is merely improbable. The split exists so the deployment can enforce the first
 * category and log the second, because a rule that is wrong in the hard category
 * takes a site down while a rule that is wrong in the soft category only adds
 * noise. Anything that is not a protocol violation is soft, however suspicious.
 *
 * @see TransportIntegrity for the catalogue of codes.
 */
final class TransportFinding
{
    public const SEVERITY_HARD = 'hard';

    public const SEVERITY_SOFT = 'soft';

    public function __construct(
        public readonly string $code,
        public readonly string $severity,
        public readonly string $detail,
    ) {}

    /**
     * A finding no conforming browser can produce.
     *
     * Reserved for requests that violate the protocol they claim to speak. See
     * the class docblock for why this category is kept separate.
     */
    public static function hard(string $code, string $detail): self
    {
        return new self($code, self::SEVERITY_HARD, $detail);
    }

    /**
     * A finding that is merely improbable.
     *
     * A real browser may produce these occasionally, so they inform a score and
     * they inform an operator; they do not on their own justify a 403.
     */
    public static function soft(string $code, string $detail): self
    {
        return new self($code, self::SEVERITY_SOFT, $detail);
    }

    public function isHard(): bool
    {
        return $this->severity === self::SEVERITY_HARD;
    }

    /**
     * @return array{code: string, severity: string, detail: string}
     */
    public function toArray(): array
    {
        return [
            'code' => $this->code,
            'severity' => $this->severity,
            'detail' => $this->detail,
        ];
    }
}

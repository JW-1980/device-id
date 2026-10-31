<?php

declare(strict_types=1);

namespace DeviceId\Detectors;

/**
 * One finding for a human: what was found, about which opaque subject, how strong it is and
 * what to do. Detectors never enforce; a host puts these in its review queue and a person
 * confirms or dismisses them.
 */
final readonly class ReviewItem
{
    public const SEVERITY_HIGH = 'high';

    public const SEVERITY_MEDIUM = 'medium';

    public const SEVERITY_INFORMATIONAL = 'informational';

    /**
     * @param  string  $detector  stable code, e.g. `accounts_per_device`
     * @param  string  $subjectKind  `device_key`, `account` or `network_hash`
     * @param  string  $subject  the host's own opaque identifier, passed through untouched
     * @param  array<string, int|float|string|bool>  $evidence  counts only, no values of a person
     */
    public function __construct(
        public string $detector,
        public string $subjectKind,
        public string $subject,
        public string $severity,
        public array $evidence,
        public string $recommendation,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return ['detector' => $this->detector, 'subject_kind' => $this->subjectKind, 'subject' => $this->subject, 'severity' => $this->severity, 'evidence' => $this->evidence, 'recommendation' => $this->recommendation];
    }
}

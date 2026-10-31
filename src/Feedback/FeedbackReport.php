<?php

declare(strict_types=1);

namespace DeviceId\Feedback;

/**
 * One report an admin made: a label from the closed vocabulary, who made it, when, and an
 * optional note. The subject (device key, observation id, account) stays with the host's own
 * row; this object is what the host stores beside it. The note is for people: it never enters a
 * training row.
 */
final readonly class FeedbackReport
{
    public const MAX_NOTES = 500;

    public function __construct(
        public string $label,
        public int $reportedAt,
        public string $reporter,
        public string $notes = '',
    ) {
        if (! FeedbackLabel::isValid($label)) {
            throw new \InvalidArgumentException("unknown feedback label '{$label}'");
        }
        if ($reporter === '') {
            throw new \InvalidArgumentException('a feedback report needs a reporter');
        }
        if (mb_strlen($notes) > self::MAX_NOTES) {
            throw new \InvalidArgumentException('a feedback note is at most '.self::MAX_NOTES.' characters');
        }
    }

    /**
     * @param  array<array-key, mixed>  $data  `label`, `reported_at`, `reporter`, `notes`
     */
    public static function tryFromArray(array $data): ?self
    {
        try {
            return is_string($data['label'] ?? null) && is_int($data['reported_at'] ?? null) && is_string($data['reporter'] ?? null)
                ? new self($data['label'], $data['reported_at'], $data['reporter'], is_string($data['notes'] ?? null) ? $data['notes'] : '')
                : null;
        } catch (\InvalidArgumentException) {
            return null;
        }
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Feedback;

/**
 * What a subject's reports add up to: the standing label (or none), and the training label and
 * weight it maps to.
 */
final readonly class FeedbackResolution
{
    /**
     * @param  string|null  $label  the standing {@see FeedbackLabel}, null when no report stands
     * @param  string|null  $trainingLabel  `honest` or the abuse kind; null when nothing stands
     * @param  int  $reports  how many reports were considered
     * @param  bool  $retracted  the last word was `clear`
     */
    public function __construct(
        public ?string $label,
        public ?string $trainingLabel,
        public float $labelWeight,
        public int $reports,
        public bool $retracted,
    ) {}

    public function isDecided(): bool
    {
        return $this->label !== null;
    }
}

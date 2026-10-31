<?php

declare(strict_types=1);

namespace DeviceId\Signals;

use DeviceId\Detectors\ReviewItem;

/**
 * One velocity result: a burst of sign-ups or sign-ins, or two sessions of an account too far
 * apart for the time between them. It scores nothing by itself; a host turns it into an account
 * flag ({@see toReviewItem()}) and into model features ({@see Velocity::features()}).
 */
final readonly class VelocityFinding
{
    public const BURST = 'velocity_burst';

    public const IMPOSSIBLE_TRAVEL = 'impossible_travel';

    /**
     * @param  array<string, int|float|string|bool>  $evidence  counts and codes only, no address
     */
    public function __construct(
        public string $code,
        public string $subjectKind,
        public string $subject,
        public string $severity,
        public array $evidence,
    ) {}

    public function toReviewItem(): ReviewItem
    {
        $recommendation = $this->code === self::IMPOSSIBLE_TRAVEL
            ? 'Compare the two sessions: a second factor or a password reset is proportionate. A VPN exit, a roaming SIM or a shared account can look like this; confirm only with a second signal.'
            : 'Look at how many distinct accounts and device keys are inside the burst before acting; a campus, an office or a carrier NAT bursts for innocent reasons.';

        return new ReviewItem($this->code, $this->subjectKind, $this->subject, $this->severity, $this->evidence, $recommendation);
    }
}

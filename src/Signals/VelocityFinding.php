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

    /** Velocity v2: too many DISTINCT accounts, devices or e-mail addresses in one window. */
    public const DISTINCT = 'velocity_distinct';

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
        $recommendation = match (true) {
            $this->code === self::IMPOSSIBLE_TRAVEL => 'Compare the two sessions: a second factor or a password reset is proportionate. A VPN exit, a roaming SIM or a shared account can look like this; confirm only with a second signal.',
            $this->code === self::DISTINCT && ($this->evidence['relation'] ?? '') === Velocity::DEVICES_PER_ACCOUNT => 'Many devices on one account: a shared or sold login, or a takeover. Ask for a second factor before a sensitive action; a family sharing a streaming-style account looks the same.',
            $this->code === self::DISTINCT && ($this->evidence['relation'] ?? '') === Velocity::ACCOUNTS_PER_DEVICE => 'Many accounts on one device: a ring, or a shared kiosk or family tablet. Look at the e-mail addresses and the creation times before acting.',
            $this->code === self::DISTINCT => 'Many distinct e-mail addresses from one network: a campus, an office or a carrier NAT does this honestly. Look at the address patterns and the devices before acting.',
            default => 'Look at how many distinct accounts and device keys are inside the burst before acting; a campus, an office or a carrier NAT bursts for innocent reasons.',
        };

        return new ReviewItem($this->code, $this->subjectKind, $this->subject, $this->severity, $this->evidence, $recommendation);
    }
}

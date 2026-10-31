<?php

declare(strict_types=1);

namespace DeviceId\Matching;

/**
 * What `DeviceMatcher` decided for one observation.
 *
 *   browser_key  the stabilised tier-1 claims are identical to a known device's (exact).
 *                FINAL (posterior 1.0) only from the candidate's own network; otherwise
 *                PROVISIONAL (`provisional`, posterior below the link threshold): a new row
 *                linked to the candidate, promoted to 1.0 only when a later report of that
 *                row arrives from the candidate's network (round-3 R3-S2 — since G-D3i the
 *                browser key is a class key shared by every unit of one model, OS release and
 *                browser major, and no client-asserted component can make it final)
 *   hardware     a candidate scored at or above the link posterior, was not tied, agreed on
 *                at least one high-entropy component and disagreed on none (a LINK)
 *   possible     a candidate scored between the possible and link posteriors — or at the
 *                link posterior but tied, or without the high-entropy evidence a link needs
 *                (`linkVeto` says which); `candidateId` is recorded as `linked_device_id`
 *   new          nothing scored; a new row is created
 *
 * `deviceId` is the device the claims MATCH; whether the caller attaches to that row or
 * creates a new row linked to it is the store's decision (round-2 decision G-D1i: the
 * `nc_vid` store never hands out an existing key; both stores never merge on a tie).
 * `clusterId` is that device's cluster root.
 *
 * `confidence` is `round(100 × coverage × posterior)`, floored at 1. It is a match
 * confidence, not a risk score, and never feeds the verdict.
 *
 * `tiedAtBest` is how many candidate clusters scored the best score (1 when one did, or
 * when the exact stage decided). A tie never links: it is demoted to `possible`.
 *
 * `protected` marks a `new` result that was decided WITHOUT matching because the key set
 * came from Firefox resistFingerprinting or Tor Browser (`DeviceKeys::$protected`): the
 * browser key of such a browser names a cohort, so it is never linked on, and the store
 * records the row as protected so nothing else links to it either.
 */
final readonly class MatchResult
{
    public const METHOD_BROWSER_KEY = 'browser_key';

    public const METHOD_HARDWARE = 'hardware';

    public const METHOD_POSSIBLE = 'possible';

    public const METHOD_NEW = 'new';

    /** A link-level posterior demoted to `possible`: two clusters scored the same. */
    public const VETO_TIED = 'tied';

    /** Demoted: no high-entropy component (fonts, gpu, voices) agreed. */
    public const VETO_NO_HIGH_ENTROPY_AGREEMENT = 'no_high_entropy_agreement';

    /** Demoted: a high-entropy component (fonts, gpu, panel) disagreed. */
    public const VETO_HIGH_ENTROPY_DISAGREEMENT = 'high_entropy_disagreement';

    /**
     * Provisional: the match came from another network than the candidate's (`link_network`).
     * A cross-network match is never final on client evidence alone (round-3 R3-S2).
     */
    public const VETO_OTHER_NETWORK = 'other_network';

    public function __construct(
        public ?int $deviceId,
        public float $posterior,
        public int $confidence,
        public string $method,
        public ?int $candidateId = null,
        public int $candidatesConsidered = 0,
        public int $tiedAtBest = 1,
        public bool $protected = false,
        public ?int $clusterId = null,
        public ?string $linkVeto = null,
        public bool $provisional = false,
    ) {}

    /**
     * The result for a protected key set: a new device, no candidate, no posterior.
     */
    public static function protectedNew(float $coverage): self
    {
        return new self(null, 0.0, self::confidenceFor($coverage, 0.0), self::METHOD_NEW, null, 0, 1, true);
    }

    /**
     * The posterior a provisional browser-key link is recorded at: strictly below the link
     * threshold, so no consumer counts the row as the same device until tier 2 promotes it.
     *
     * @param  array{link_posterior: float, possible_posterior: float}  $settings
     */
    public static function provisionalPosterior(array $settings): float
    {
        return round(max(0.0, min($settings['possible_posterior'], $settings['link_posterior'] - 0.0001)), 4);
    }

    /**
     * A matcher posterior kept as computed but capped strictly below the link threshold: the
     * posterior a PROVISIONAL hardware link (a cross-network match) is recorded at (R3-S2).
     *
     * @param  array{link_posterior: float}  $settings
     */
    public static function belowLink(float $posterior, array $settings): float
    {
        return round(max(0.0, min($posterior, $settings['link_posterior'] - 0.0001)), 4);
    }

    public function isTied(): bool
    {
        return $this->tiedAtBest > 1;
    }

    public function isLink(): bool
    {
        return $this->deviceId !== null;
    }

    public function isPossible(): bool
    {
        return $this->method === self::METHOD_POSSIBLE;
    }

    /**
     * The device this result names, linked or possible: the target of `linked_device_id`.
     */
    public function targetId(): ?int
    {
        return $this->deviceId ?? $this->candidateId;
    }

    public static function confidenceFor(float $coverage, float $posterior): int
    {
        $coverage = max(0.0, min(1.0, $coverage));
        $posterior = max(0.0, min(1.0, $posterior));

        return max(1, (int) round(100 * $coverage * $posterior));
    }
}

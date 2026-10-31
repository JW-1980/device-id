<?php

declare(strict_types=1);

namespace DeviceId\Scoring;

/**
 * What a visit would have scored under the weights an operator is testing, next to what it did
 * score. Data for a log and an admin screen; it changes nothing.
 */
final readonly class ShadowComparison
{
    /**
     * @param  list<array{code: string, live_weight: int, shadow_weight: int, fired: bool}>  $changes  every tested code with its two weights; `fired` says whether the rule matched this visit
     */
    public function __construct(
        public int $liveWeight,
        public int $shadowWeight,
        public int $liveScore,
        public int $shadowScore,
        public string $liveBand,
        public string $shadowBand,
        public array $changes,
    ) {}

    public function wouldChangeBand(): bool
    {
        return $this->liveBand !== $this->shadowBand;
    }

    /** Whether any tested rule actually fired on this visit, i.e. the test had a say. */
    public function hadEffect(): bool
    {
        return $this->liveWeight !== $this->shadowWeight;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'live' => ['weight' => $this->liveWeight, 'score' => $this->liveScore, 'band' => $this->liveBand],
            'shadow' => ['weight' => $this->shadowWeight, 'score' => $this->shadowScore, 'band' => $this->shadowBand],
            'would_change_band' => $this->wouldChangeBand(),
            'changes' => $this->changes,
        ];
    }
}

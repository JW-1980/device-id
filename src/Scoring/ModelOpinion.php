<?php

declare(strict_types=1);

namespace DeviceId\Scoring;

use DeviceId\Model\Contribution;

/**
 * What the statistical model thinks of one visit, as data a host can log and an operator can
 * read. It is an opinion: whether it changes the verdict is decided by the mode
 * ({@see ModelScorer}), and `applied` says whether it did.
 *
 * `adjustmentWeight` is the signed weight the model WOULD add as one `model_adjustment`
 * disagreement after every bound (cap, rule-family floor, no-block-alone, hard-transport
 * floor); in `shadow` and `advise` it is computed and logged but not applied, which is what
 * lets the owner see what `bounded` would have done before turning it on.
 * `suggestsReview` is true when the bounds stopped the adjustment from reaching `block`: the
 * host may open a human-reviewed hold (the owner's 48-hour decision).
 */
final readonly class ModelOpinion
{
    /**
     * @param  list<Contribution>  $contributions  sorted by absolute weight
     */
    public function __construct(
        public string $state,
        public string $mode,
        public ?string $modelId = null,
        public ?float $probability = null,
        public ?float $rulesProbability = null,
        public int $adjustmentWeight = 0,
        public array $contributions = [],
        public bool $applied = false,
        public bool $suggestsReview = false,
        public string $reason = '',
    ) {}

    /**
     * Rules decide: the model is off, missing, stale, incompatible, corrupt or failed.
     */
    public static function unavailable(string $state, string $mode, string $reason = ''): self
    {
        return new self($state, $mode, reason: $reason);
    }

    public function isUsable(): bool
    {
        return $this->probability !== null;
    }

    /**
     * The `model_adjustment` disagreement, or null when the opinion adds nothing.
     *
     * @return array{code: string, detail: string, weight: int}|null
     */
    public function disagreement(): ?array
    {
        if ($this->adjustmentWeight === 0) {
            return null;
        }

        $top = array_map(
            static fn (Contribution $c): string => sprintf('%s %+.2f', $c->feature, $c->weight),
            array_slice($this->contributions, 0, 3),
        );

        return [
            'code' => ModelScorer::CODE,
            'detail' => sprintf('model %s p=%.3f; %s', $this->modelId ?? '?', $this->probability ?? 0.0, implode(', ', $top)),
            'weight' => $this->adjustmentWeight,
        ];
    }

    /**
     * The JSON a host stores in `fingerprint_observations.model_opinion`: no feature VALUES of
     * a person, only feature names and their logit contributions.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'mode' => $this->mode,
            'model_id' => $this->modelId,
            'p' => $this->probability === null ? null : round($this->probability, 4),
            'p_rules' => $this->rulesProbability === null ? null : round($this->rulesProbability, 4),
            'adjustment' => $this->adjustmentWeight,
            'applied' => $this->applied,
            'suggests_review' => $this->suggestsReview,
            'contributions' => array_map(static fn (Contribution $c): array => $c->toArray(), array_slice($this->contributions, 0, 5)),
            'reason' => $this->reason,
        ];
    }
}

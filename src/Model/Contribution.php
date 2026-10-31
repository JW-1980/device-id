<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * One feature's share of a prediction, in logit units: `weight` is the coefficient times the
 * feature value. The list of these is the explanation shown beside the verdict.
 */
final readonly class Contribution
{
    public function __construct(public string $feature, public float $value, public float $weight) {}

    /**
     * @return array{feature: string, value: float, weight: float}
     */
    public function toArray(): array
    {
        return ['feature' => $this->feature, 'value' => $this->value, 'weight' => round($this->weight, 6)];
    }
}

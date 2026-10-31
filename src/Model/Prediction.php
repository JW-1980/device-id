<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * A model's answer: the calibrated probability of "not an honest visitor", the raw logit and
 * the contributions sorted by absolute weight (largest first).
 */
final readonly class Prediction
{
    /**
     * @param  list<Contribution>  $contributions
     */
    public function __construct(public float $probability, public float $logit, public array $contributions, public string $modelId) {}

    /**
     * @return list<Contribution>
     */
    public function top(int $count = 3): array
    {
        return array_slice($this->contributions, 0, $count);
    }
}

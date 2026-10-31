<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * A calibrated logistic regression evaluated in plain PHP: `z = intercept + sum(coef * x)`,
 * `p = sigmoid(a * z + b)` (Platt scaling). Nothing else - no library, no extension - so the
 * evaluator is small enough to be pinned line by line by golden tests.
 *
 * Contributions are `coef * x` in raw logit units, sorted by absolute size. They sum to
 * `z - intercept` exactly, which is the property that makes the explanation honest.
 */
final readonly class LogisticModel
{
    /**
     * @param  list<string>  $features
     * @param  list<float>  $coefficients
     * @param  array{a: float, b: float}  $calibration
     * @param  array{a: float, b: float}|null  $rulesCalibration  maps the rules' total weight to a probability on the same data
     * @param  array<string, mixed>  $document  the validated JSON document
     */
    public function __construct(
        public string $id,
        public array $features,
        public array $coefficients,
        public float $intercept,
        public array $calibration,
        public ?array $rulesCalibration,
        public int $maxAdjustmentWeight,
        public int $minRuleFamilies,
        public ?int $trainedAt,
        public array $document,
    ) {}

    /**
     * @param  array<string, float>  $features  only non-zero features need be present
     */
    public function predict(array $features): Prediction
    {
        $logit = $this->intercept;
        $contributions = [];
        foreach ($this->features as $index => $name) {
            $value = $features[$name] ?? 0.0;
            if ($value === 0.0) {
                continue;
            }
            $weight = $this->coefficients[$index] * $value;
            $logit += $weight;
            $contributions[] = new Contribution($name, $value, $weight);
        }

        usort($contributions, static fn (Contribution $a, Contribution $b): int => abs($b->weight) <=> abs($a->weight) ?: strcmp($a->feature, $b->feature));

        return new Prediction(self::sigmoid($this->calibration['a'] * $logit + $this->calibration['b']), $logit, $contributions, $this->id);
    }

    /**
     * The probability the rules' total weight alone implies on the training data, or null when
     * the model carries no rules calibration.
     */
    public function rulesProbability(int $totalWeight): ?float
    {
        if ($this->rulesCalibration === null) {
            return null;
        }

        return self::sigmoid($this->rulesCalibration['a'] * $totalWeight + $this->rulesCalibration['b']);
    }

    public static function sigmoid(float $z): float
    {
        return 1.0 / (1.0 + exp(-max(-35.0, min(35.0, $z))));
    }

    public static function logit(float $p): float
    {
        $p = max(1e-9, min(1.0 - 1e-9, $p));

        return log($p / (1.0 - $p));
    }
}

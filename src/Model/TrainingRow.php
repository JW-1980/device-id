<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * One de-identified training example: the feature vector, a label, and just enough context to
 * split without leaking (`group`) and to evaluate per slice. It carries no value a person typed,
 * no address, no identifier ({@see TrainingRowBuilder} builds them and enforces that).
 *
 * `label` is one of {@see LABELS}; `isPositive()` is "not an honest visitor". `labelWeight` is
 * the confidence of the label source (a honeypot hit is 1.0, a CAPTCHA abandon 0.3).
 * `rulesWeight` is the total weight of the emitted rule disagreements, which is what the rules
 * alone would have scored: the baseline every model is compared against on the same rows.
 */
final readonly class TrainingRow
{
    public const LABELS = ['honest', 'automation', 'headless', 'spoof', 'fraud'];

    /**
     * @param  array<string, float>  $features
     * @param  array{engine: string, device: string, privacy: string}  $slice  engine chromium|gecko|webkit|unknown, device mobile|desktop|unknown, privacy protected|none
     */
    public function __construct(
        public array $features,
        public string $label,
        public string $group,
        public array $slice,
        public int $rulesWeight,
        public float $labelWeight = 1.0,
        public string $source = 'unknown',
        public string $id = '',
    ) {}

    public function isPositive(): bool
    {
        return $this->label !== 'honest';
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id, 'features' => $this->features, 'label' => $this->label, 'group' => $this->group,
            'slice' => $this->slice, 'rules_weight' => $this->rulesWeight, 'label_weight' => $this->labelWeight, 'source' => $this->source,
        ];
    }

    /**
     * @param  array<array-key, mixed>  $data
     */
    public static function fromArray(array $data): ?self
    {
        $label = $data['label'] ?? null;
        $features = $data['features'] ?? null;
        $slice = $data['slice'] ?? [];
        if (! is_string($label) || ! in_array($label, self::LABELS, true) || ! is_array($features) || ! is_string($data['group'] ?? null)) {
            return null;
        }
        $clean = [];
        foreach ($features as $name => $value) {
            if (! is_string($name) || ! is_numeric($value)) {
                return null;
            }
            $clean[$name] = (float) $value;
        }

        return new self(
            $clean, $label, $data['group'],
            [
                'engine' => is_string($slice['engine'] ?? null) ? $slice['engine'] : 'unknown',
                'device' => is_string($slice['device'] ?? null) ? $slice['device'] : 'unknown',
                'privacy' => is_string($slice['privacy'] ?? null) ? $slice['privacy'] : 'none',
            ],
            (int) ($data['rules_weight'] ?? 0),
            is_numeric($data['label_weight'] ?? null) ? max(0.0, min(1.0, (float) $data['label_weight'])) : 1.0,
            is_string($data['source'] ?? null) ? $data['source'] : 'unknown',
            is_string($data['id'] ?? null) ? $data['id'] : '',
        );
    }
}

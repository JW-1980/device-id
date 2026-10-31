<?php

declare(strict_types=1);

namespace DeviceId\Matching;

/**
 * Fellegi-Sunter component weights as data: per component an AGREE weight and a DISAGREE
 * weight (asymmetric, unlike the hand table), in bits (log2 of the likelihood ratio), plus the
 * pair counts per slice that decide whether they may be promoted.
 *
 * ## Why promotion is a data property and not a switch
 *
 * The estimate is only as good as the population it saw. The owner's decision is that weights
 * are used for linking only when EVERY slice has at least {@see MIN_PAIRS_PER_SLICE} pairs;
 * until then the file may be loaded in shadow mode and nothing else. {@see promotion()} says
 * which slices are short, so the report can name them.
 *
 * @phpstan-type Weight array{agree: float, disagree: float, m_agree: float, u_agree: float, m_disagree: float, u_disagree: float, n: int}
 */
final readonly class LearnedWeights
{
    public const SCHEMA = 'device-id.matcher-weights';

    public const SCHEMA_VERSION = 1;

    public const MIN_PAIRS_PER_SLICE = 1000;

    /**
     * @param  array<string, Weight>  $weights
     * @param  array<string, int>  $sliceCounts  slice => number of pairs the estimate saw
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public array $weights,
        public float $priorLogit,
        public array $sliceCounts,
        public array $metadata = [],
    ) {}

    /**
     * @param  array<string, bool>  $comparisons  component => agrees
     */
    public function logit(array $comparisons): float
    {
        $bits = 0.0;
        foreach ($comparisons as $component => $agrees) {
            $weight = $this->weights[$component] ?? null;
            if ($weight !== null) {
                $bits += $agrees ? $weight['agree'] : $weight['disagree'];
            }
        }

        return $this->priorLogit + $bits * M_LN2;
    }

    /**
     * @param  array<string, bool>  $comparisons
     */
    public function posterior(array $comparisons): float
    {
        return round(1.0 / (1.0 + exp(-$this->logit($comparisons))), 4);
    }

    /**
     * @param  array<string, bool>  $comparisons
     * @return array<string, float> component => bits contributed
     */
    public function contributions(array $comparisons): array
    {
        $out = [];
        foreach ($comparisons as $component => $agrees) {
            $weight = $this->weights[$component] ?? null;
            if ($weight !== null) {
                $out[$component] = $agrees ? $weight['agree'] : $weight['disagree'];
            }
        }

        return $out;
    }

    /**
     * @return array{promotable: bool, short_slices: array<string, int>, minimum: int}
     */
    public function promotion(int $minimum = self::MIN_PAIRS_PER_SLICE): array
    {
        $short = [];
        foreach ($this->sliceCounts as $slice => $count) {
            if ($count < $minimum) {
                $short[$slice] = $count;
            }
        }

        return ['promotable' => $this->sliceCounts !== [] && $short === [], 'short_slices' => $short, 'minimum' => $minimum];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'schema' => self::SCHEMA,
            'schema_version' => self::SCHEMA_VERSION,
            'prior_logit' => $this->priorLogit,
            'weights' => $this->weights,
            'slice_counts' => $this->sliceCounts,
            'metadata' => $this->metadata,
        ];
    }

    /**
     * @param  array<array-key, mixed>  $data
     */
    public static function fromArray(array $data): ?self
    {
        if (($data['schema'] ?? null) !== self::SCHEMA || ($data['schema_version'] ?? null) !== self::SCHEMA_VERSION
            || ! is_array($data['weights'] ?? null) || ! is_numeric($data['prior_logit'] ?? null)) {
            return null;
        }

        $weights = [];
        foreach ($data['weights'] as $component => $weight) {
            if (! is_string($component) || ! is_array($weight)) {
                return null;
            }
            foreach (['agree', 'disagree', 'm_agree', 'u_agree', 'm_disagree', 'u_disagree'] as $key) {
                if (! is_numeric($weight[$key] ?? null)) {
                    return null;
                }
            }
            $weights[$component] = [
                'agree' => (float) $weight['agree'], 'disagree' => (float) $weight['disagree'],
                'm_agree' => (float) $weight['m_agree'], 'u_agree' => (float) $weight['u_agree'],
                'm_disagree' => (float) $weight['m_disagree'], 'u_disagree' => (float) $weight['u_disagree'],
                'n' => (int) ($weight['n'] ?? 0),
            ];
        }

        $slices = [];
        foreach (is_array($data['slice_counts'] ?? null) ? $data['slice_counts'] : [] as $slice => $count) {
            $slices[(string) $slice] = (int) $count;
        }

        return new self($weights, (float) $data['prior_logit'], $slices, is_array($data['metadata'] ?? null) ? $data['metadata'] : []);
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Scoring;

use DeviceId\CheckRegistry;
use DeviceId\Model\FeatureCatalogue;
use DeviceId\Model\LogisticModel;
use DeviceId\Model\ModelSpec;
use DeviceId\Reputation\ReputationResult;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;
use DeviceId\Support\Verdict;

/**
 * The calibrated model as a bounded second opinion on top of the rules.
 *
 * ## Modes (`fingerprint.model.mode`)
 *
 * - `off`: nothing is computed.
 * - `shadow`: the opinion is computed for logging; the verdict is untouched.
 * - `advise`: as shadow, and the host shows the opinion beside the rule list.
 * - `bounded`: the opinion becomes ONE disagreement, `model_adjustment`, inside the verdict.
 *
 * ## The bounds (each pinned by a test)
 *
 * 1. The adjustment is a disagreement like any other, so the score still reconstructs from
 *    `Verdict::totalWeight()`.
 * 2. It is capped at `max_adjustment_weight` (default 20, never above the rule ceiling of 60).
 * 3. A POSITIVE adjustment is emitted only when the rules found contradictions in at least
 *    `min_rule_families_for_escalation` (default 2) distinct families AND as many distinct
 *    evidence groups ({@see CheckRegistry::groupsOf()}), so one root cause is never escalated.
 *    A visitor with no contradiction is never touched, whatever the model thinks.
 * 4. The model never moves a verdict into `block` that the rules had not: the adjustment is
 *    reduced to stay below it and `suggestsReview` is set, so the host can open a
 *    human-reviewed hold instead. Rules-only blocks are unchanged. Together with the evidence
 *    groups this proves that one root cause plus the model never blocks: one cause is one
 *    group, at most `EnvironmentConsistency::MAX_WEIGHT` (45, score 68, not `block`), and the
 *    adjustment is reduced until the band is not `block` (at 0 it is the rules' band).
 * 5. A NEGATIVE adjustment (the model vouching for the visitor) is bounded the same way and can
 *    never take a verdict below `elevated` while hard transport evidence is present: the
 *    client cannot rewrite that evidence, so no statistical model may argue it away.
 * 6. An allowed visitor (verified crawler, monitor, operator list) is never adjusted.
 * 7. Any failure - no file, stale, wrong schema, tampered, an exception - falls back to the
 *    rules, with the state on the opinion. A model fault must never fail an ingest.
 *
 * ## How the weight is chosen
 *
 * The rules' effective weight is turned into a probability by a calibration fitted on the same
 * calibration split as the model's own Platt scaling (`rules_calibration`, slope `a` per weight
 * unit); neither is fitted on the validation rows the promotion metrics are measured on. The adjustment is the weight
 * the rules would have needed to say what the model says:
 * `(logit(p_model) - logit(p_rules)) / a`. Both probabilities share one training prior, so the
 * prior cancels.
 */
final class ModelScorer
{
    public const CODE = 'model_adjustment';

    public const MODE_OFF = 'off';

    public const MODE_SHADOW = 'shadow';

    public const MODE_ADVISE = 'advise';

    public const MODE_BOUNDED = 'bounded';

    /** @var array<string, array{mtime: int|false, load: array{state: string, model: LogisticModel|null, reason: string}}> */
    private static array $loaded = [];

    /**
     * @param  array{state: string, model: LogisticModel|null, reason: string}  $load
     */
    public function __construct(
        private readonly VerdictScorer $scorer,
        private readonly array $load,
        private readonly string $mode = self::MODE_SHADOW,
        private readonly int $maxAdjustmentWeight = 20,
        private readonly bool $allowDeescalation = true,
    ) {}

    /**
     * From `fingerprint.model.*` ({@see Config}): `mode`, `path`, `max_age_days`,
     * `max_adjustment_weight`, `allow_deescalation`. The file is read once per process and
     * re-read when its modification time changes.
     */
    public static function fromConfig(VerdictScorer $scorer, ?int $now = null): self
    {
        $mode = Config::raw('fingerprint.model.mode', self::MODE_OFF);
        $mode = is_string($mode) && in_array($mode, [self::MODE_OFF, self::MODE_SHADOW, self::MODE_ADVISE, self::MODE_BOUNDED], true) ? $mode : self::MODE_OFF;
        $path = Config::raw('fingerprint.model.path');

        $load = ['state' => ModelSpec::STATE_OFF, 'model' => null, 'reason' => 'mode is off'];
        if ($mode !== self::MODE_OFF) {
            if (! is_string($path) || $path === '') {
                $load = ['state' => ModelSpec::STATE_ABSENT, 'model' => null, 'reason' => 'fingerprint.model.path is not set'];
            } else {
                $mtime = @filemtime($path);
                $maxAge = max(1, Config::int('fingerprint.model.max_age_days', 45));
                $key = $path.'|'.$maxAge;
                // Staleness depends on the clock, so a cached "ok" is re-checked against it.
                if (! isset(self::$loaded[$key]) || self::$loaded[$key]['mtime'] !== $mtime || $now !== null) {
                    self::$loaded[$key] = ['mtime' => $mtime, 'load' => ModelSpec::load($path, $maxAge, $now)];
                }
                $load = self::$loaded[$key]['load'];
            }
        }

        return new self(
            $scorer,
            $load,
            $mode,
            max(0, min(EnvironmentConsistency::MAX_WEIGHT, Config::int('fingerprint.model.max_adjustment_weight', 20))),
            Config::bool('fingerprint.model.allow_deescalation', true),
        );
    }

    public static function forgetLoadedModels(): void
    {
        self::$loaded = [];
    }

    public function mode(): string
    {
        return $this->mode;
    }

    /**
     * The model's opinion of a visit the rules have already scored.
     */
    /**
     * @param  array<string, float>  $reputation  {@see ReputationResult::features()}, when the host has IP reputation
     */
    public function opinionFor(ScoredClaims $scored, array $reputation = []): ModelOpinion
    {
        $omitted = 0;
        foreach ($scored->omission as $entry) {
            $omitted += count($entry['omitted'] ?? []);
        }

        return $this->opinion($scored->verdict, $scored->integrityCount, $scored->confidence->score, count($scored->untrusted), $omitted, $scored->protectedCohortRecent !== null, $reputation);
    }

    /**
     * @param  array<string, float>  $reputation
     */
    public function opinion(Verdict $verdict, int $integrityCount = 0, ?int $coverageScore = null, int $untrustedCount = 0, int $omissionCount = 0, bool $protected = false, array $reputation = []): ModelOpinion
    {
        if ($this->mode === self::MODE_OFF) {
            return ModelOpinion::unavailable(ModelSpec::STATE_OFF, $this->mode);
        }
        $model = $this->load['model'];
        if ($this->load['state'] !== ModelSpec::STATE_OK || $model === null) {
            return ModelOpinion::unavailable($this->load['state'], $this->mode, $this->load['reason']);
        }

        try {
            $rules = array_values(array_filter($verdict->disagreements, static fn (array $d): bool => $d['code'] !== self::CODE));
            $features = FeatureCatalogue::build($rules, $integrityCount, $coverageScore, $untrustedCount, $omissionCount, $protected, $reputation);
            $prediction = $model->predict($features);
            $rulesWeight = CheckRegistry::effectiveWeight($rules);
            $rulesProbability = $model->rulesProbability($rulesWeight);

            [$weight, $review] = $this->boundedAdjustment($model, $verdict, $rules, $prediction->probability, $rulesProbability, $rulesWeight);

            return new ModelOpinion(
                ModelSpec::STATE_OK, $this->mode, $model->id, $prediction->probability, $rulesProbability,
                $weight, $prediction->contributions, false, $review,
            );
        } catch (\Throwable $e) {
            return ModelOpinion::unavailable(ModelSpec::STATE_ERROR, $this->mode, get_class($e));
        }
    }

    /**
     * Applies an opinion to the rules' verdict: only in `bounded` mode, only with a usable,
     * non-zero opinion, never to allowed traffic.
     */
    public function apply(Verdict $verdict, ModelOpinion $opinion): Verdict
    {
        $disagreement = $opinion->disagreement();
        if ($this->mode !== self::MODE_BOUNDED || ! $opinion->isUsable() || $disagreement === null || $verdict->isAllowed()) {
            return $verdict;
        }

        $rules = array_values(array_filter($verdict->disagreements, static fn (array $d): bool => $d['code'] !== self::CODE));

        return $this->scorer->merged($rules, [$disagreement], $verdict->confidence, $verdict->deviceKey, $verdict->saltVersion);
    }

    /**
     * Opinion and application in one call: the verdict (changed only in `bounded`) and the opinion
     * with `applied` set truthfully.
     *
     * @return array{0: Verdict, 1: ModelOpinion}
     */
    public function score(ScoredClaims $scored, array $reputation = []): array
    {
        $opinion = $this->opinionFor($scored, $reputation);
        $verdict = $this->apply($scored->verdict, $opinion);
        $applied = $verdict !== $scored->verdict;

        return [$verdict, $applied ? new ModelOpinion(
            $opinion->state, $opinion->mode, $opinion->modelId, $opinion->probability, $opinion->rulesProbability,
            $opinion->adjustmentWeight, $opinion->contributions, true, $opinion->suggestsReview, $opinion->reason,
        ) : $opinion];
    }

    /**
     * @param  list<array{code: string, detail: string, weight: int}>  $rules
     * @return array{0: int, 1: bool} the signed weight after every bound, and whether a block was withheld
     */
    private function boundedAdjustment(LogisticModel $model, Verdict $verdict, array $rules, float $probability, ?float $rulesProbability, int $rulesWeight): array
    {
        if ($rules === [] || $rulesProbability === null || $model->rulesCalibration === null || $model->rulesCalibration['a'] <= 0.0 || $verdict->isAllowed()) {
            return [0, false];
        }

        $cap = min($this->maxAdjustmentWeight, $model->maxAdjustmentWeight, EnvironmentConsistency::MAX_WEIGHT);
        $raw = (LogisticModel::logit($probability) - LogisticModel::logit($rulesProbability)) / $model->rulesCalibration['a'];
        $weight = (int) max(-$cap, min($cap, round($raw)));

        // Escalation needs independent evidence: enough families AND enough evidence groups, so
        // one root cause that shows up in two families (a UA lie: transport and environment)
        // is never escalated by the model.
        if ($weight > 0 && (count(FeatureCatalogue::families($rules)) < $model->minRuleFamilies || count(CheckRegistry::groupsOf($rules)) < $model->minRuleFamilies)) {
            return [0, false];
        }
        if ($weight < 0 && ! $this->allowDeescalation) {
            return [0, false];
        }

        $review = false;
        $rulesScore = $this->scorer->scoreFor($rulesWeight);
        $rulesBand = $this->scorer->bandFor($rulesScore);

        if ($weight > 0 && $rulesBand !== Verdict::BAND_BLOCK) {
            while ($weight > 0 && $this->scorer->bandFor($this->scorer->scoreFor($rulesWeight + $weight)) === Verdict::BAND_BLOCK) {
                $weight--;
                $review = true;
            }
        }

        if ($weight < 0 && $this->hasHardTransportEvidence($rules)) {
            $floor = min($rulesScore, $this->elevatedScore());
            while ($weight < 0 && $this->scorer->scoreFor($rulesWeight + $weight) < $floor) {
                $weight++;
            }
        }

        return [$weight, $review];
    }

    private function elevatedScore(): int
    {
        $bands = Config::array('fingerprint.bands');

        return is_numeric($bands[Verdict::BAND_ELEVATED] ?? null) ? (int) $bands[Verdict::BAND_ELEVATED] : 40;
    }

    /**
     * Transport findings are evidence the client cannot rewrite (family `transport`, or a
     * derived `transport_*` code).
     *
     * @param  list<array{code: string, weight: int}>  $rules
     */
    private function hasHardTransportEvidence(array $rules): bool
    {
        foreach ($rules as $rule) {
            if (CheckRegistry::familyOf($rule['code']) === 'transport' || str_starts_with($rule['code'], 'transport_')) {
                return true;
            }
        }

        return false;
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Support;

/**
 * The outcome of evaluating a claim set: a band, a score, and the evidence.
 *
 * ## Why the score is reconstructible from `disagreements` alone
 *
 * That is a hard requirement, not a nicety. An automatic decision nobody can explain
 * is an automatic decision nobody can defend, and the person who has to defend it is
 * an operator at 03:00 looking at an admin screen. `VerdictScorerTest` therefore
 * asserts the identity `score === f(sum of disagreement weights)` as a property of
 * every verdict it builds — if the scoring ever gains a term the disagreements do not
 * explain, the test fails rather than the audit trail quietly diverging from the
 * number.
 *
 * ## Why `reasons` is codes and not prose
 *
 * Because a code is greppable and prose is not. "Why was this blocked?" has to be
 * answerable with a search across months of rows, and the detail sentences are free to
 * be reworded at any time. The codes are the stable half.
 */
final readonly class Verdict
{
    public const BAND_PASS = 'pass';

    public const BAND_ELEVATED = 'elevated';

    public const BAND_CHALLENGE = 'challenge';

    public const BAND_BLOCK = 'block';

    /**
     * The traffic decision, one answer for a host (see `TrafficGate`). An allowed request is
     * never challenged or blocked, whatever its fingerprint says.
     */
    public const ALLOW_VERIFIED_CRAWLER = 'ALLOW_VERIFIED_CRAWLER';

    public const ALLOW_VERIFIED_MONITOR = 'ALLOW_VERIFIED_MONITOR';

    public const ALLOW_LISTED = 'ALLOW_LISTED';

    public const DECISION_SCORE = 'SCORE';

    /**
     * @param  list<array{code: string, detail: string, weight: int}>  $disagreements
     * @param  list<string>  $reasons  stable codes, sorted
     * @param  Confidence|null  $confidence  how much of the measurement surface
     *                                       answered, 1-100. ORTHOGONAL to `$score`: it is coverage, not risk, and it
     *                                       never contributes to the band. See `Confidence` for why coupling the two
     *                                       is the one thing that must never happen.
     */
    public function __construct(
        public string $band,
        public int $score,
        public array $reasons,
        public array $disagreements,
        public ?string $deviceKey = null,
        public int $saltVersion = 0,
        public ?Confidence $confidence = null,
        /** One of the `ALLOW_*` markers when the traffic is allowed, else null. */
        public ?string $allowance = null,
    ) {}

    /**
     * @return list<string>
     */
    public static function bands(): array
    {
        return [self::BAND_PASS, self::BAND_ELEVATED, self::BAND_CHALLENGE, self::BAND_BLOCK];
    }

    /**
     * A verdict for a claim set that produced nothing at all.
     *
     * ## This is a security requirement, and it is the one people get wrong
     *
     * Gummy Browsers breaks fingerprint-based authentication with a true-positive
     * rate above 0.9 from a *single* harvest of the victim's fingerprint. A
     * fingerprint is therefore a **risk signal, never a credential** — and the direct
     * consequence is that a visitor whose browser declines to collect signals is an
     * ordinary visitor, not a suspicious one.
     *
     * Scoring "no fingerprint" as risk is the easiest way to build a system that bans
     * privacy-protective browsers while still being defeated by a determined attacker:
     * it rejects the honest users who declined and rewards anyone who simply
     * suppresses collection. See `REPORT.md` §10.6.
     */
    public static function nothingCollected(): self
    {
        return new self(self::BAND_PASS, 0, [], [], null, 0);
    }

    /**
     * This verdict marked as allowed traffic: the band is `pass`, so a host that only reads the
     * band skips challenge and block. Without `$keepAnalysis` the score, reasons and disagreements
     * are cleared (a crawler is not expected to have a fingerprint, so there is nothing to explain);
     * with it they are kept for analysis only, and the score still reconstructs from the
     * disagreements even though the band no longer follows from it.
     */
    public function withAllowance(string $allowance, bool $keepAnalysis = false): self
    {
        return new self(
            self::BAND_PASS,
            $keepAnalysis ? $this->score : 0,
            $keepAnalysis ? $this->reasons : [],
            $keepAnalysis ? $this->disagreements : [],
            $this->deviceKey,
            $this->saltVersion,
            $this->confidence,
            $allowance,
        );
    }

    public function isAllowed(): bool
    {
        return $this->allowance !== null;
    }

    /** `ALLOW_*` when allowed, else `SCORE`: the band is then the decision. */
    public function decision(): string
    {
        return $this->allowance ?? self::DECISION_SCORE;
    }

    public function isPass(): bool
    {
        return $this->band === self::BAND_PASS;
    }

    public function hasReason(string $code): bool
    {
        return in_array($code, $this->reasons, true);
    }

    /**
     * The sum of disagreement weights, which the score is a function of.
     *
     * Public so the score's reconstructibility is assertable from outside rather than
     * taken on trust.
     */
    public function totalWeight(): int
    {
        $total = 0;
        foreach ($this->disagreements as $disagreement) {
            $total += $disagreement['weight'];
        }

        return $total;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $array = [
            'band' => $this->band,
            'score' => $this->score,
            'reasons' => $this->reasons,
            'disagreements' => $this->disagreements,
            'salt_version' => $this->saltVersion,
        ];

        if ($this->allowance !== null) {
            $array['allowance'] = $this->allowance;
        }

        return $array;
    }
}

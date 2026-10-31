<?php

declare(strict_types=1);

namespace DeviceId\Scoring;

use DeviceId\CheckRegistry;
use DeviceId\Network\NetworkFacts;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Confidence;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;
use DeviceId\Support\Verdict;

/**
 * Turns contradictions into a band, and is the only place a decision is made.
 *
 * ## Score the COUNT of disagreements, not the sum of signal scores
 *
 * This is the central design decision and it is the one `REPORT.md` §3.8 argues for.
 *
 * The tempting alternative is to score each signal's trustworthiness and add them up.
 * That is wrong in a specific way: it lets a client that controls *all* of its own
 * signals decide its own score. Spoof every value perfectly and a sum-of-scores model
 * reports a perfectly trustworthy client, because the numbers it supplied were
 * excellent numbers.
 *
 * A disagreement cannot be spoofed the same way, because one half of it is something
 * the transport proved. Counting contradictions inverts the incentive: a client can
 * only lower its score by *not lying*, and lying raises the count.
 *
 * ## Correlated rules count once: evidence groups
 *
 * Two rules may be perfectly correlated (they read one underlying fact) or wholly
 * independent, and a plain weighted sum cannot tell. The skeptical review (H2) measured
 * the cost: one User-Agent override fired three rules on one fact, summed to 95 and
 * blocked a real Chromium. The score is therefore computed from the EFFECTIVE weight
 * ({@see CheckRegistry::effectiveWeight()}): rules that share evidence are declared in one
 * evidence group and the group counts once, at its heaviest member. Independent groups
 * still add up, so two independent contradictions still beat one.
 *
 * What remains a limitation: the groups are declared from the rules' inputs, not learned
 * from traffic, and between groups the arithmetic is still a sum. Two groups of equal
 * effective weight score the same however the weight is distributed
 * (`VerdictScorerTest::the_same_total_weight_scores_the_same_however_it_is_distributed`).
 *
 * ## What actually keeps real visitors safe
 *
 * Not the curve. Two things:
 *
 * 1. **Each weak rule is genuinely weak** (4-8), and five of them — more than any
 *    honest browser produces — do not reach the block band. The curve is asymptotic, so
 *    it cannot promise that "no amount of stacking" stays under `block`; that claim is
 *    false for any finite divisor and a test asserting it fails.
 * 2. **Enforcement is off by default** behind a seven-day log review, per the
 *    `security.transport_integrity.enforce_codes` note in config.
 *
 * The first version of this docblock claimed the asymptotic property the curve does not
 * have. It was corrected when a test caught it.
 *
 * ## The curve
 *
 * `score = min(100, round(100 * (1 - exp(-weight / 40))))`
 *
 * Diminishing returns. The divisor of 40 is calibrated so the heaviest single evidence
 * group (45, `EnvironmentConsistency::MAX_WEIGHT`, which also clamps operator overrides)
 * alone lands at 68 — `challenge` territory — and never `block`. A host that lowers the
 * divisor or the block threshold can break that; {@see singleCauseCanBlock()} reports it.
 */
final class VerdictScorer
{
    public function __construct(private readonly EnvironmentConsistency $consistency) {}

    /**
     * @param  array<array-key, mixed>  $claims  a decoded claim set
     * @param  NetworkFacts|null  $network  what the local IP data says about the address (null: no network rules run)
     */
    public function score(
        array $claims,
        TransportIntegrityResult $transport,
        ?string $deviceKey = null,
        int $saltVersion = 0,
        ?Confidence $confidence = null,
        ?NetworkFacts $network = null,
    ): Verdict {
        $disagreements = $this->consistency->contradictions($claims, $transport, $network);

        // Transport findings join the same list, at their own weights, so there is one
        // scoring path rather than a transport score and a claim score that then have
        // to be combined by a rule nobody can reconstruct.
        foreach ($this->transportDisagreements($transport) as $finding) {
            $disagreements[] = $finding;
        }

        if ($disagreements === []) {
            return new Verdict(
                Verdict::BAND_PASS,
                0,
                [],
                [],
                $deviceKey,
                $saltVersion,
                $confidence,
            );
        }

        $weight = CheckRegistry::effectiveWeight($disagreements);
        $reasons = [];
        foreach ($disagreements as $disagreement) {
            $reasons[] = $disagreement['code'];
        }

        // Sorted and deduplicated so two observations of the same contradiction
        // produce the same `reasons` list, which is what makes it greppable across
        // rows. Two views of one problem is one reason, not two.
        $reasons = array_values(array_unique($reasons));
        sort($reasons, SORT_STRING);

        $score = $this->scoreFor($weight);

        return new Verdict(
            $this->bandFor($score),
            $score,
            $reasons,
            $disagreements,
            $deviceKey,
            $saltVersion,
            $confidence,
        );
    }

    /**
     * A verdict over an already-collected disagreement list: the union of a stored
     * observation's contradictions and a later envelope's, one entry per code, rescored on
     * the same curve as {@see score()} (round-2 CQ-21: `FingerprintIngest` used to carry
     * its own copy of this assembly).
     *
     * @param  array<array-key, mixed>  $stored
     * @param  list<array{code: string, detail: string, weight: int}>  $fresh
     */
    public function merged(array $stored, array $fresh, ?Confidence $confidence = null, ?string $deviceKey = null, int $saltVersion = 0): Verdict
    {
        $byCode = [];
        foreach ([...$stored, ...$fresh] as $disagreement) {
            if (! is_array($disagreement)) {
                continue;
            }
            $code = $disagreement['code'] ?? null;
            $weight = $disagreement['weight'] ?? null;
            $detail = $disagreement['detail'] ?? '';
            if (! is_string($code) || $code === '' || ! is_int($weight) || isset($byCode[$code])) {
                continue;
            }
            $byCode[$code] = ['code' => $code, 'detail' => is_string($detail) ? $detail : '', 'weight' => $weight];
        }

        $disagreements = array_values($byCode);
        if ($disagreements === []) {
            return new Verdict(Verdict::BAND_PASS, 0, [], [], $deviceKey, $saltVersion, $confidence);
        }

        $weight = CheckRegistry::effectiveWeight($disagreements);
        $reasons = array_keys($byCode);
        sort($reasons, SORT_STRING);
        $score = $this->scoreFor($weight);

        return new Verdict($this->bandFor($score), $score, $reasons, $disagreements, $deviceKey, $saltVersion, $confidence);
    }

    /**
     * The diminishing curve. Public so the reconstructibility test can call it.
     */
    public function scoreFor(int $weight): int
    {
        if ($weight <= 0) {
            return 0;
        }

        $divisor = max(1, Config::int('fingerprint.score_divisor', 40));

        return (int) min(100, round(100 * (1 - exp(-$weight / $divisor))));
    }

    /**
     * True when the host's scoring configuration (divisor and bands) lets ONE evidence group at
     * the rule ceiling reach `block`, breaking the "no single root cause blocks" invariant. A
     * settings screen should refuse such a configuration on save.
     */
    public function singleCauseCanBlock(): bool
    {
        return $this->bandFor($this->scoreFor(EnvironmentConsistency::MAX_WEIGHT)) === Verdict::BAND_BLOCK;
    }

    public function bandFor(int $score): string
    {
        $thresholds = Config::array('fingerprint.bands');
        $challenge = is_numeric($thresholds[Verdict::BAND_CHALLENGE] ?? null) ? (int) $thresholds[Verdict::BAND_CHALLENGE] : 60;
        $block = is_numeric($thresholds[Verdict::BAND_BLOCK] ?? null) ? (int) $thresholds[Verdict::BAND_BLOCK] : 80;
        $elevated = is_numeric($thresholds[Verdict::BAND_ELEVATED] ?? null) ? (int) $thresholds[Verdict::BAND_ELEVATED] : 40;

        return match (true) {
            $score >= $block => Verdict::BAND_BLOCK,
            $score >= $challenge => Verdict::BAND_CHALLENGE,
            $score >= $elevated => Verdict::BAND_ELEVATED,
            default => Verdict::BAND_PASS,
        };
    }

    /**
     * Transport findings as disagreements, so they score on the same curve.
     *
     * A hard transport finding is a protocol violation — the strongest evidence this
     * system has, and something no browser produces. A soft finding is merely
     * improbable.
     *
     * Both weights come from the same tunable table as the claim-side rules, which is
     * why they are looked up rather than written here. They were literals in this
     * method at first, and the consequence was that `weightOf()` returned the generic
     * default for every transport code — so an operator reading the weights table saw
     * no transport entries and had no way to retune them without editing PHP.
     *
     * The two fallbacks exist because a hard finding's code is specific
     * (`transport_sec_ch_full_version_mismatch`) and a soft finding's code may be
     * anything, so there is no single soft key to look up.
     *
     * @return list<array{code: string, detail: string, weight: int}>
     */
    private function transportDisagreements(TransportIntegrityResult $transport): array
    {
        $out = [];
        $weights = EnvironmentConsistency::weights();

        foreach ($transport->findings as $finding) {
            $code = 'transport_'.$finding->code;

            $out[] = [
                'code' => $code,
                'detail' => $finding->detail,
                'weight' => $weights[$code] ?? ($weights['transport_'.($finding->isHard() ? 'default' : 'soft_default')] ?? 0),
            ];
        }

        return $out;
    }
}

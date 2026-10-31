<?php

declare(strict_types=1);

namespace DeviceId\Scoring;

use DeviceId\Support\Confidence;
use DeviceId\Support\Verdict;

/**
 * Everything the scorers decided about one envelope, as the rows store it: the verdict,
 * the coverage confidence with the probe states and penalties it was computed from, the
 * omission measurement, the components the evidence made untrusted, and the integrity
 * finding count (CQ-21).
 */
final readonly class ScoredClaims
{
    /**
     * @param  array<string, string>  $states  `tier:probe` => ok|unavailable|absent
     * @param  list<string>  $reasons
     * @param  array<string, array{expected: int, omitted: list<string>, probe_set?: int}>  $omission
     * @param  list<string>  $untrusted  component names the evidence of this visit makes untrusted
     * @param  list<string>  $integrityCodes  every effective integrity code this visit already paid
     *                                        for, reported or server-derived, independent of rule
     *                                        weights (`IntegrityFindings::effective()`)
     * @param  int|null  $protectedCohortRecent  for a protected visit, the protected rows of its
     *                                           cohort key and network within the velocity window
     */
    public function __construct(
        public Verdict $verdict,
        public Confidence $confidence,
        public array $states,
        public int $penalty,
        public array $reasons,
        public array $omission,
        public array $untrusted,
        public int $integrityCount,
        public array $integrityCodes = [],
        public ?int $protectedCohortRecent = null,
    ) {}

    /**
     * The `probe_states` JSON of an observation: STATES, never values, plus the link the
     * tier-1 match decided (`link`), which the tier-2 envelope reads back so a browser-key
     * identity is final (round-2 R2-01 / R2-03) — the tier-2 envelope carries no tier-1
     * claims, so it cannot re-derive it. `integrity_codes` lets tier 2 skip a fact tier 1
     * already paid for; `protected_cohort_recent` is present for a protected visit only.
     *
     * @param  array{method: string, posterior: float, target: int|null}|null  $link
     * @return array<string, mixed>
     */
    public function probeStates(?array $link): array
    {
        return array_filter(
            [
                'states' => $this->states,
                'penalty' => $this->penalty,
                'reasons' => $this->reasons,
                'omission' => $this->omission,
                'untrusted' => $this->untrusted,
                'integrity_codes' => $this->integrityCodes,
                'protected_cohort_recent' => $this->protectedCohortRecent,
                'link' => $link,
            ],
            static fn (mixed $value, string $key): bool => $value !== null || $key === 'link',
            ARRAY_FILTER_USE_BOTH,
        );
    }

    /**
     * The same scores with the protected-cohort count of a protected visit, which is only
     * known inside the transaction that created its row.
     */
    public function withProtectedCohortRecent(int $count): self
    {
        return new self($this->verdict, $this->confidence, $this->states, $this->penalty, $this->reasons, $this->omission, $this->untrusted, $this->integrityCount, $this->integrityCodes, $count);
    }

    /**
     * How many weighted probes answered, across tiers.
     */
    public function answeredCount(): int
    {
        return count(array_filter($this->states, static fn (string $state): bool => $state === ConfidenceScorer::STATE_OK));
    }
}

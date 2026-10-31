<?php

declare(strict_types=1);

namespace DeviceId\Support;

/**
 * How much of the expected measurement surface actually answered, as 1-100.
 *
 * ## This is COVERAGE, not probability
 *
 * The distinction is the whole point, and it is the thing most implementations get
 * wrong. A number produced by a single tab cannot say how likely it is that a future
 * visit is the same device, because it has not seen a future visit. Nothing running in
 * one page load has any evidence about cross-visit identity. So a "70% sure this is the
 * same device" claim from local data alone is a guess wearing a percentage sign.
 *
 * What a single page load *can* honestly report is: how much of what we asked for did we
 * get? That is coverage, it is measurable, and it is what this is.
 *
 * WhorlID, the only comparable public implementation found, makes the same distinction
 * in almost exactly these words — and it is the reason this class exists in that form
 * rather than as a `confidence` float on the verdict.
 *
 * ## Why coverage is worth having at all
 *
 * Because it is the one honest way to talk about a partial measurement. The rule this
 * system holds is "missing data is never evidence" — an empty claim set scores 0 and
 * lands in `pass`, because scoring absence as risk is how a control ends up banning
 * privacy-protective browsers.
 *
 * That rule is correct and it has a cost: a visitor with no JavaScript and a bot that
 * suppressed collection are indistinguishable in the risk score. Coverage is how the
 * difference becomes visible WITHOUT turning it into risk. A no-JS visitor is
 * `risk 0 / confidence 3`; a clean desktop browser is `risk 0 / confidence 88`. Neither
 * is penalised, and the difference is legible to an operator.
 *
 * ## What this number must never be used for
 *
 * It must never raise the risk score. Doing so re-creates exactly the bug recorded in
 * notes/07 §1, where a check that read "no signals" as "suspicious" flagged honest
 * warm-cache visitors. Risk and coverage are orthogonal, and coupling them is the single
 * easiest way to turn this into a tool that punishes privacy-protective browsers.
 *
 * It must never gate access either. This is a measurement-quality metric, not a
 * credential, for the same reason a verdict is not one.
 */
final readonly class Confidence
{
    /**
     * Floor. A score of 0 would be indistinguishable from "not computed", and
     * downstream code that checks `> 0` would then be checking the wrong thing. The
     * prompt asked for 1-100, and 1 is a defensible floor: something always answered,
     * even if only the transport.
     */
    public const MINIMUM = 1;

    public const MAXIMUM = 100;

    /**
     * @param  int  $score  1-100
     * @param  int  $earned  weight actually credited
     * @param  int  $expected  weight that could have been earned
     * @param  list<string>  $missing  probes that did not answer, tier-qualified
     * @param  list<string>  $penalties  reasons the score was reduced
     */
    public function __construct(
        public int $score,
        public int $earned,
        public int $expected,
        public array $missing = [],
        public array $penalties = [],
    ) {}

    /**
     * The coverage ratio before penalties, 0.0-1.0.
     *
     * Null when nothing was expected at all, which is a different fact from "expected
     * and got none". This system has been bitten by that conflation twice — once in the
     * removed subresource check and once in the disabled audio rule — so an unknown is
     * never rendered as a zero.
     */
    public function coverage(): ?float
    {
        if ($this->expected < 1) {
            return null;
        }

        return round($this->earned / $this->expected, 3);
    }

    /**
     * Is this a measurement worth acting on?
     *
     * A threshold, deliberately conservative, and deliberately NOT a risk input. It
     * answers "was this measurement mostly collected", nothing more.
     */
    public function isSubstantial(): bool
    {
        return $this->score >= 50;
    }

    /**
     * @return array{score: int, coverage: float|null, missing: list<string>, penalties: list<string>}
     */
    public function toArray(): array
    {
        return [
            'score' => $this->score,
            'coverage' => $this->coverage(),
            'missing' => $this->missing,
            'penalties' => $this->penalties,
        ];
    }
}

<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Crawlers;

use NutriCompare\Fingerprint\Support\TransportFinding;
use NutriCompare\Fingerprint\Support\Verdict;

/**
 * The one answer a host gets for a request: allowed (and why), or "score it normally".
 *
 * `decision` is one of `Verdict::ALLOW_LISTED`, `Verdict::ALLOW_VERIFIED_CRAWLER`,
 * `Verdict::ALLOW_VERIFIED_MONITOR`, or `Verdict::DECISION_SCORE`. An allowed request must not be
 * challenged, blocked, rate-limited into errors, or shown anything different from what a visitor
 * sees (allowing is not cloaking).
 */
final readonly class TrafficClassification
{
    public function __construct(
        public string $decision,
        public CrawlerVerification $verification,
        /** `ip` or `device_key` when the operator allowlist matched. */
        public ?string $listedBy = null,
        /** The allowlist entry or monitor key that matched. */
        public ?string $matched = null,
        /** A monitor the User-Agent names while the address is not on its list. Log at most. */
        public ?string $unlistedMonitorClaim = null,
    ) {}

    public function isAllowed(): bool
    {
        return $this->decision !== Verdict::DECISION_SCORE;
    }

    /**
     * Whether the host should expect (or ask for) a fingerprint at all. An allowed or declared
     * crawler is not a browser and has none; scoring it on its absence would be the bug.
     */
    public function fingerprintExpected(): bool
    {
        return ! $this->isAllowed() && ! $this->verification->claimsCrawler();
    }

    /**
     * A claimed crawler whose proof was contradicted: the impersonation signal, as a transport
     * finding the engine scores (weight `transport_crawler_impersonation`, 45).
     */
    public function impersonationFinding(): ?TransportFinding
    {
        return self::impersonationFindingFor($this->verification);
    }

    public static function impersonationFindingFor(CrawlerVerification $verification): ?TransportFinding
    {
        if (! $verification->isForged()) {
            return null;
        }

        return TransportFinding::hard(
            'crawler_impersonation',
            'The User-Agent claims to be '.($verification->crawler ?? 'a search crawler').' but '
                .($verification->hostname === CrawlerVerification::RANGE_EVIDENCE
                    ? 'the address is not in the vendor\'s published IP list.'
                    : 'reverse DNS'.($verification->hostname !== null ? ' ('.$verification->hostname.')' : '').' does not forward-confirm the vendor.'),
        );
    }

    /**
     * The verdict with this classification applied. Allowed traffic gets the allowance marker and
     * the pass band; the claims' evidence is kept for analysis only when `$keepAnalysis` is set.
     */
    public function applyTo(Verdict $verdict, bool $keepAnalysis = false): Verdict
    {
        return $this->isAllowed() ? $verdict->withAllowance($this->decision, $keepAnalysis) : $verdict;
    }
}

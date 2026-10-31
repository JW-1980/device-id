<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * Puts the e-mail module together for one sign-up address: normalisation, the local domain lists,
 * the cached mail-domain check and the local-part heuristics. Request-safe: it reads caches only
 * and makes no network call. Everything it cannot establish is `null` / `unknown`, never "clean".
 *
 * The output is {@see EmailAssessment}: soft features and reason codes. A disposable address
 * alone never blocks; it is one input among many, and the weights live with the host's rules and
 * the model.
 */
final class EmailAssessor
{
    public function __construct(
        private readonly DomainLists $lists,
        private readonly ?DomainMailCheck $mailCheck = null,
    ) {}

    public function assess(string $email): EmailAssessment
    {
        $parsed = EmailNormalizer::parse($email);
        if ($parsed === null) {
            return EmailAssessment::invalid();
        }

        $facts = $this->lists->lookup($parsed->canonicalDomain === 'gmail.com' ? 'gmail.com' : $parsed->domain);
        $class = match (true) {
            $facts->disposable === true => EmailAssessment::CLASS_DISPOSABLE,
            $facts->forwarding === true => EmailAssessment::CLASS_FORWARDING,
            $facts->free === true => EmailAssessment::CLASS_FREE,
            $facts->state === DomainFacts::STATE_UNAVAILABLE => EmailAssessment::CLASS_UNKNOWN,
            default => EmailAssessment::CLASS_OTHER,
        };

        return new EmailAssessment(
            $class,
            $facts->disposable,
            $facts->free,
            $facts->forwarding,
            $this->mailCheck?->peek($parsed->domain) ?? DomainMailCheck::UNKNOWN,
            GeneratedAddress::assess($parsed->local, $facts->forwarding === true)['level'],
            $parsed->tag !== null,
        );
    }

    /**
     * Job side: whether to run the DNS check for this address now, and the outcome. A domain that
     * is a known free provider or disposable is not worth a lookup.
     */
    public function checkDomain(string $email): string
    {
        $parsed = EmailNormalizer::parse($email);
        if ($parsed === null || $this->mailCheck === null) {
            return DomainMailCheck::UNKNOWN;
        }
        if (! DomainMailCheck::shouldCheck($this->lists->lookup($parsed->domain))) {
            return $this->mailCheck->peek($parsed->domain);
        }

        return $this->mailCheck->refresh($parsed->domain);
    }
}

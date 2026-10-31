<?php

declare(strict_types=1);

namespace DeviceId\Email;

use DeviceId\Crawlers\CrawlerCache;

/**
 * The optional "can this domain receive mail?" check, split so DNS never runs on a request:
 *
 * - {@see refresh()} is the JOB (a queue worker, a scheduler): it asks the {@see MailDnsResolver}
 *   and stores the outcome per domain.
 * - {@see peek()} is the REQUEST side: it reads the cache only and answers `ok`, `no_mail` or
 *   `unknown`. A domain nobody has checked yet is `unknown`.
 *
 * ## Fail safe
 *
 * - `no_mail` needs the resolver to say so on TWO checks at least `confirmAfterSeconds` apart
 *   (default one hour). The first one only records a strike; a DNS outage, a flapping
 *   authoritative server or a single bad answer cannot flag a domain.
 * - `unknown` from the resolver never changes a stored outcome (a good answer is not forgotten
 *   because DNS was down for a minute) and never counts as a strike.
 * - An answer of `ok` clears the strikes and is remembered `okTtl` seconds (24 h); `no_mail` is
 *   remembered `noMailTtl` seconds (1 h) so a domain whose MX is fixed is re-checked soon.
 * - A check is only worth running for a domain that is neither a known free provider nor a known
 *   disposable domain ({@see shouldCheck()}).
 *
 * `no_mail` is a VALIDATION result, not a fraud verdict: the address cannot receive the
 * confirmation mail, so the host asks the person to correct it.
 */
final class DomainMailCheck
{
    public const OK = 'ok';

    public const NO_MAIL = 'no_mail';

    public const UNKNOWN = 'unknown';

    private const PREFIX = 'device-id:mailcheck:';

    /**
     * @param  (\Closure(): int)|null  $clock
     */
    public function __construct(
        private readonly ?MailDnsResolver $resolver = null,
        private readonly ?CrawlerCache $cache = null,
        private readonly ?\Closure $clock = null,
        private readonly int $okTtlSeconds = 86400,
        private readonly int $noMailTtlSeconds = 3600,
        private readonly int $confirmAfterSeconds = 3600,
    ) {}

    /**
     * Whether a job should spend a DNS lookup on this domain.
     */
    public static function shouldCheck(DomainFacts $facts): bool
    {
        return $facts->free !== true && $facts->disposable !== true && $facts->forwarding !== true;
    }

    /**
     * Request side: the cached outcome, never a lookup.
     *
     * @return self::OK|self::NO_MAIL|self::UNKNOWN
     */
    public function peek(string $domain): string
    {
        $domain = DomainLists::normaliseDomain($domain);
        $entry = $domain === null ? null : $this->cache?->get(self::PREFIX.hash('sha256', $domain));

        return is_array($entry) && in_array($entry['status'] ?? null, [self::OK, self::NO_MAIL], true) ? $entry['status'] : self::UNKNOWN;
    }

    /**
     * Job side: ask DNS and store the outcome. Returns what {@see peek()} answers afterwards.
     *
     * @return self::OK|self::NO_MAIL|self::UNKNOWN
     */
    public function refresh(string $domain): string
    {
        $domain = DomainLists::normaliseDomain($domain);
        if ($domain === null || $this->resolver === null || $this->cache === null) {
            return self::UNKNOWN;
        }
        $key = self::PREFIX.hash('sha256', $domain);
        $now = $this->currentTime();
        $entry = $this->cache->get($key);
        $previous = is_array($entry) ? $entry : [];

        try {
            $answer = $this->resolver->mailStatus($domain);
        } catch (\Throwable) {
            $answer = MailDnsResolver::UNKNOWN;
        }

        if ($answer === MailDnsResolver::MAIL_OK) {
            $this->cache->put($key, ['status' => self::OK, 'at' => $now, 'strikes' => 0], $this->okTtlSeconds);

            return self::OK;
        }
        if ($answer !== MailDnsResolver::NO_MAIL) {
            return $this->peek($domain);
        }

        $firstStrike = (int) ($previous['first_strike_at'] ?? 0);
        $strikes = (int) ($previous['strikes'] ?? 0);
        if ($strikes === 0 || $firstStrike === 0) {
            $strikes = 1;
            $firstStrike = $now;
        } elseif ($now - $firstStrike >= $this->confirmAfterSeconds) {
            $strikes++;
        }
        $confirmed = $strikes >= 2;
        $this->cache->put($key, [
            // A confirmed absence replaces the stored status; an unconfirmed one keeps the last good one.
            'status' => $confirmed ? self::NO_MAIL : (is_string($previous['status'] ?? null) ? $previous['status'] : self::UNKNOWN),
            'at' => $now,
            'strikes' => $strikes,
            'first_strike_at' => $firstStrike,
        ], $confirmed ? $this->noMailTtlSeconds : max($this->noMailTtlSeconds, $this->confirmAfterSeconds * 2));

        return $this->peek($domain);
    }

    private function currentTime(): int
    {
        return $this->clock === null ? time() : ($this->clock)();
    }
}

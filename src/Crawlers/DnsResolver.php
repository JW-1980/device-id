<?php

declare(strict_types=1);

namespace DeviceId\Crawlers;

/**
 * The DNS the host provides. Both calls are blocking network operations, so the verifier is
 * driven from a background step, never from the request path.
 *
 * Contract: a failure of any kind (no answer, timeout, exception) is reported as "no answer",
 * never as an answer. The verifier turns "no answer" into `unverifiable`, which is never allowed.
 */
interface DnsResolver
{
    /**
     * The PTR name of an address, or null when there is no answer.
     */
    public function reverse(string $ip): ?string;

    /**
     * Every A and AAAA address of a hostname; an empty list when there is no answer.
     *
     * @return list<string>
     */
    public function forward(string $hostname): array;
}

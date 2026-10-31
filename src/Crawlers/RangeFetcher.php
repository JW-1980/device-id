<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Crawlers;

/**
 * Fetches a vendor's published IP list for the host.
 *
 * The host owns the transport policy and should apply it: HTTPS only, no redirects followed, a
 * body size cap, a timeout, and SSRF screening of the resolved address (the URLs come from
 * configuration an operator can edit). Return the body of a 2xx response, or null for anything
 * else, including exceptions. The directory treats null as "unavailable", never as "empty".
 */
interface RangeFetcher
{
    public function fetch(string $url): ?string;
}

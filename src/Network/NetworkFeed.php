<?php

declare(strict_types=1);

namespace DeviceId\Network;

use DeviceId\Reputation\FeedDefinition;

/**
 * One local-data download: where it is, what it contains, the licence finding that decides
 * whether it may be used, and how long it stays trustworthy.
 *
 * `urls` are tried in order; `{YYYY-MM}` is replaced with the current month and then the
 * previous one (a monthly file is published during the month, so the first days of a new month
 * may only have last month's). `licence` has the same shape and statuses as
 * {@see FeedDefinition}.
 */
final readonly class NetworkFeed
{
    /** Ranges to an ISO 3166-1 alpha-2 country code. */
    public const KIND_COUNTRY = 'country';

    /** Ranges to an autonomous system number, with its registered name (classified at refresh). */
    public const KIND_ASN = 'asn';

    /** A plain list of ASNs that are known to be hosting, cloud or colocation. */
    public const KIND_HOSTING_ASN_LIST = 'hosting_asn_list';

    /**
     * @param  list<string>  $urls
     * @param  array{status: string, note: string, source: string, checked_on: string}  $licence
     */
    public function __construct(
        public string $key,
        public string $name,
        public array $urls,
        public string $kind,
        public array $licence,
        public string $attribution = '',
        /** Never fetch again before this many seconds have passed since the last attempt. */
        public int $minimumRefreshSeconds = 86400,
        /** Younger than this: fresh, no refresh due. */
        public int $freshSeconds = 172800,
        /** Older than this: ignored (a stale list is no evidence), never read as clean. */
        public int $maxAgeSeconds = 1209600,
    ) {}

    public function isUsableWithout(): bool
    {
        return in_array($this->licence['status'], ['permitted', 'permitted_with_attribution'], true);
    }
}

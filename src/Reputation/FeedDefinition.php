<?php

declare(strict_types=1);

namespace DeviceId\Reputation;

/**
 * One published IP list: where it is, how to read it, what it says about an address, and the
 * licence finding that decides whether it may be used at all.
 *
 * `licence` is a finding with a source and a date, not a guess: `permitted` (the publisher
 * states free use including commercial), `permitted_with_notice` (a copyright or licence NOTICE
 * must travel with the copy of the data, kept in `LICENSE-THIRD-PARTY.md`; nothing is shown to
 * visitors), `unverified` (published for use but no licence text was found: usable only when the
 * host accepts it explicitly), `public_credit_required` (the publisher demands a visible credit
 * or a link back; never loaded, because a credit would reveal a detection method) or
 * `not_compatible` (a licence that forbids commercial use; never loaded).
 */
final readonly class FeedDefinition
{
    public const FORMAT_IP_LINES = 'ip_lines';

    public const FORMAT_CIDR_LINES = 'cidr_lines';

    public const FORMAT_NDJSON_CIDR = 'ndjson_cidr';

    public const FORMAT_AWS = 'aws_json';

    public const FORMAT_GCP = 'gcp_json';

    public const FORMAT_ORACLE = 'oracle_json';

    public const FORMAT_CSV_FIRST_COLUMN = 'csv_first_column';

    /**
     * The Tor Project's CollecTor exit-list directory (`@type tordnsel 1.0`, CC0): `url` is the
     * directory index, the newest file in it is fetched and its `ExitAddress` lines are read.
     */
    public const FORMAT_TORDNSEL_DIRECTORY = 'tordnsel_directory';

    public const CATEGORY_DATACENTER = 'datacenter';

    public const CATEGORY_TOR_EXIT = 'tor_exit';

    public const CATEGORY_ABUSE_LIST = 'abuse_list';

    public const LICENCE_PERMITTED = 'permitted';

    public const LICENCE_PERMITTED_WITH_NOTICE = 'permitted_with_notice';

    public const LICENCE_PUBLIC_CREDIT_REQUIRED = 'public_credit_required';

    public const LICENCE_UNVERIFIED = 'unverified';

    public const LICENCE_NOT_COMPATIBLE = 'not_compatible';

    /**
     * @param  array{status: string, note: string, source: string, checked_on: string}  $licence
     */
    public function __construct(
        public string $key,
        public string $name,
        public string $url,
        public string $format,
        public string $category,
        public array $licence,
        /** Non-empty means the publisher demands a visible credit: the feed is then never loaded. */
        public string $attribution = '',
        /** Never fetch more often than this. */
        public int $minimumRefreshSeconds = 86400,
    ) {}

    public function isUsableWithout(): bool
    {
        return $this->attribution === ''
            && in_array($this->licence['status'], [self::LICENCE_PERMITTED, self::LICENCE_PERMITTED_WITH_NOTICE], true);
    }
}

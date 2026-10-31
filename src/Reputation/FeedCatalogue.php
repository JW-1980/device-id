<?php

declare(strict_types=1);

namespace DeviceId\Reputation;

/**
 * The feeds the package knows, with the licence finding for each (checked 2026-10-31 against
 * the publishers' own pages; re-check before relying on it, terms change).
 *
 * ## Included
 *
 * - Spamhaus DROP (IPv4 and IPv6): "free for any use, including in products"; credit to the
 *   Spamhaus Project must be given, automated downloads at least one hour apart, the data
 *   must not be fetched from the website more than once a day. EDROP is merged into DROP
 *   (2024-04-10), so there is no separate feed. The Spamhaus name must not be used in
 *   commercial materials. The DROP Fair Use Policy page was read only in part; hosts that
 *   redistribute (rather than use) the data should read it in full.
 * - Cloud ranges (AWS, Google Cloud, Oracle Cloud, DigitalOcean): published by each provider
 *   so that customers can identify its traffic. No licence text was found on any of them, so
 *   they are `unverified`: loaded only when the host accepts them by key.
 * - Tor Project bulk exit list: a public service whose page states no licence: `unverified`.
 *
 * ## Deliberately NOT included
 *
 * - FireHOL level1 (and every FireHOL list): the repository states no licence and says "IP Lists
 *   are a property of their maintainers" and that some carry special licences; level1 is built
 *   from DShield, Feodo Tracker, fullbogons and Spamhaus DROP, and DShield data is licensed
 *   Creative Commons NonCommercial (ShareAlike), which is NOT compatible with commercial use.
 *   Use Spamhaus DROP directly instead.
 * - Microsoft Azure: the download URL contains the publication date and changes weekly (a
 *   host supplies it); no licence text on the download page.
 * - Hetzner: no official published range list was found (only third-party aggregators of the
 *   BGP announcements); a host that wants it must source it from RIPE itself.
 * - DShield / SANS ISC data, and any commercial reputation service.
 */
final class FeedCatalogue
{
    /**
     * @return array<string, FeedDefinition>
     */
    public static function defaults(): array
    {
        $dropLicence = [
            'status' => FeedDefinition::LICENCE_PERMITTED_WITH_ATTRIBUTION,
            'note' => 'Free for any use incl. products; credit Spamhaus Project; downloads at least 1 hour apart and not more than once a day; do not use the Spamhaus name in commercial materials. Fair Use Policy only partly read.',
            'source' => 'https://www.spamhaus.org/drop/',
            'checked_on' => '2026-10-31',
        ];
        $published = static fn (string $source): array => [
            'status' => FeedDefinition::LICENCE_UNVERIFIED,
            'note' => 'Published by the provider so customers can identify its traffic; no licence text found.',
            'source' => $source,
            'checked_on' => '2026-10-31',
        ];

        $feeds = [
            new FeedDefinition('spamhaus_drop_v4', 'Spamhaus DROP (IPv4)', 'https://www.spamhaus.org/drop/drop_v4.json', FeedDefinition::FORMAT_NDJSON_CIDR, FeedDefinition::CATEGORY_ABUSE_LIST, $dropLicence, 'Contains data from the Spamhaus Project DROP list (https://www.spamhaus.org/drop/).', 86400),
            new FeedDefinition('spamhaus_drop_v6', 'Spamhaus DROP (IPv6)', 'https://www.spamhaus.org/drop/drop_v6.json', FeedDefinition::FORMAT_NDJSON_CIDR, FeedDefinition::CATEGORY_ABUSE_LIST, $dropLicence, 'Contains data from the Spamhaus Project DROP list (https://www.spamhaus.org/drop/).', 86400),
            new FeedDefinition('tor_exit', 'Tor Project bulk exit list', 'https://check.torproject.org/torbulkexitlist', FeedDefinition::FORMAT_IP_LINES, FeedDefinition::CATEGORY_TOR_EXIT, [
                'status' => FeedDefinition::LICENCE_UNVERIFIED,
                'note' => 'Public Tor Project service; its page states no licence or terms.',
                'source' => 'https://check.torproject.org/torbulkexitlist',
                'checked_on' => '2026-10-31',
            ], '', 3600),
            new FeedDefinition('aws', 'AWS IP ranges', 'https://ip-ranges.amazonaws.com/ip-ranges.json', FeedDefinition::FORMAT_AWS, FeedDefinition::CATEGORY_DATACENTER, $published('https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html')),
            new FeedDefinition('gcp', 'Google Cloud IP ranges', 'https://www.gstatic.com/ipranges/cloud.json', FeedDefinition::FORMAT_GCP, FeedDefinition::CATEGORY_DATACENTER, $published('https://cloud.google.com/vpc/docs/subnets')),
            new FeedDefinition('oracle', 'Oracle Cloud public IP ranges', 'https://docs.oracle.com/iaas/tools/public_ip_ranges.json', FeedDefinition::FORMAT_ORACLE, FeedDefinition::CATEGORY_DATACENTER, $published('https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm')),
            new FeedDefinition('digitalocean', 'DigitalOcean IP ranges', 'https://www.digitalocean.com/geo/google.csv', FeedDefinition::FORMAT_CSV_FIRST_COLUMN, FeedDefinition::CATEGORY_DATACENTER, $published('https://www.digitalocean.com/geo/google.csv')),
        ];

        $out = [];
        foreach ($feeds as $feed) {
            $out[$feed->key] = $feed;
        }

        return $out;
    }
}

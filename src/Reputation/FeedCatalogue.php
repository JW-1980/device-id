<?php

declare(strict_types=1);

namespace DeviceId\Reputation;

use DeviceId\Signals\NetworkReputation;

/**
 * The feeds the package knows, with the licence finding for each (checked 2026-10-31 against
 * the publishers' own pages; re-check before relying on it, terms change).
 *
 * ## The rule for this catalogue: no source that needs PUBLIC credit
 *
 * A credit on a public page would reveal a detection method, so a feed whose publisher demands
 * one (or a link back) is not in the catalogue, and {@see FeedDefinition::isUsableWithout()}
 * refuses to load any feed that carries an attribution text. Copyright notices that only have to
 * travel with the data are kept in `LICENSE-THIRD-PARTY.md`.
 *
 * ## Included
 *
 * - **Tor exit list** from the Tor Project's CollecTor (`@type tordnsel 1.0`, hourly): Tor
 *   Metrics states "Data on this site is freely available under a CC0 no copyright
 *   declaration" (https://metrics.torproject.org/about.html). The newest file of the directory is
 *   read; its `ExitAddress` lines are the addresses relays actually exited from.
 * - Cloud ranges (AWS, Google Cloud, Oracle Cloud, DigitalOcean): published by each provider
 *   so that customers can identify its traffic. No licence text was found on any of them, so
 *   they are `unverified`: loaded only when the host accepts them by key. None asks for credit.
 *
 * ## Deliberately NOT included
 *
 * - **Spamhaus DROP**: "when used in a product, credit for the use must be given to The Spamhaus
 *   Project", and its Fair Use Policy forbids the Spamhaus name in commercial materials. Removed
 *   2026-10-31. No free list of hijacked netblocks under CC0 or PDDL was found (searched
 *   2026-10-31; abuse.ch's botnet lists name command-and-control servers, not visitors, and their
 *   page was not reachable to check the terms; FireHOL and DShield are NonCommercial), so the abuse signal comes from the host's own history instead
 *   ({@see NetworkReputation}) plus the hosting, Tor and bad-asn signals. The
 *   `abuse_list` category stays for a list the HOST supplies under a licence of its own.
 * - FireHOL level1 (and every FireHOL list): the repository states no licence and says "IP Lists
 *   are a property of their maintainers"; level1 is built from DShield (Creative Commons
 *   NonCommercial), which is NOT compatible with commercial use.
 * - Microsoft Azure: the download URL contains the publication date and changes weekly (a
 *   host supplies it); the Microsoft terms limit "Documents" to non-commercial use.
 * - Hetzner: no official published range list was found.
 * - DShield / SANS ISC data, and any commercial reputation service.
 */
final class FeedCatalogue
{
    /**
     * @return array<string, FeedDefinition>
     */
    public static function defaults(): array
    {
        $published = static fn (string $source): array => [
            'status' => FeedDefinition::LICENCE_UNVERIFIED,
            'note' => 'Published by the provider so customers can identify its traffic; no licence text found.',
            'source' => $source,
            'checked_on' => '2026-10-31',
        ];

        $feeds = [
            new FeedDefinition('tor_exit', 'Tor exit list (CollecTor tordnsel)', 'https://collector.torproject.org/recent/exit-lists/', FeedDefinition::FORMAT_TORDNSEL_DIRECTORY, FeedDefinition::CATEGORY_TOR_EXIT, [
                'status' => FeedDefinition::LICENCE_PERMITTED,
                'note' => 'Tor Metrics: "Data on this site is freely available under a CC0 no copyright declaration"; CollecTor lists the exit lists as @type tordnsel 1.0. No credit, no notice.',
                'source' => 'https://metrics.torproject.org/about.html',
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

<?php

declare(strict_types=1);

namespace DeviceId\Network;

/**
 * The local datasets the package can load, with the licence finding for each (checked
 * 2026-10-31 against the publishers' own pages and the files themselves; re-check before
 * relying on it, terms change).
 *
 * ## Included (no account, no key, free for commercial use)
 *
 * - **DB-IP "IP to Country Lite"** (CC BY 4.0): monthly CSV, `start,end,CC`, IPv4 and IPv6.
 *   Attribution is required; for a web application DB-IP asks for the link
 *   `<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>` on pages that use the results. A page
 *   that only scores a sign-in and shows the visitor nothing is not displaying results, but the
 *   host's licence notice should carry the line anyway. {@see NetworkFacts::$attribution}.
 * - **IPtoASN combined** (Public Domain, PDDL 1.0): hourly TSV `start end ASN country name`. The
 *   country in this file is the ASN's registration country, NOT where the address is, so it is
 *   never used as a geolocation; only the ASN and the name (for {@see AsnClassifier}) are read.
 * - **bad-asn-list** (MIT, Brian Hamachek): about 740 ASNs of hosting, cloud and colocation
 *   providers, a CSV `ASN,Entity`. A single-maintainer list, so it only adds ASNs the name
 *   classifier missed, and it is ignored after a year.
 *
 * ## Deliberately NOT included
 *
 * - **MaxMind GeoLite2**: needs an account and a licence key, and its EULA grants use "for your
 *   own internal business purposes", forbids disclosing the data to third parties without
 *   MaxMind's consent, and requires destroying superseded versions within 30 days. Usable in
 *   principle by an application that is its own sole user, but not account-free and not
 *   something a shared package should fetch for its hosts. Not shipped.
 * - **DB-IP City / ASN Lite**: same licence as the country file and larger; the city is not
 *   needed, and IPtoASN is public domain for the ASN. (A host that wants DB-IP's ASN file can
 *   add a feed of kind `asn`.)
 * - **X4BNet/lists_vpn and IPLocate**: the generated lists are MIT but derive from the IPLocate
 *   database (CC BY-SA 4.0, share-alike); not included.
 * - **A free list of VPN ASNs with a licence**: none was found. VPN detection is therefore the
 *   name classifier on the IPtoASN registered names, which finds a VPN company that says so in
 *   its name and misses one that does not.
 */
final class NetworkFeedCatalogue
{
    /**
     * @return array<string, NetworkFeed>
     */
    public static function defaults(): array
    {
        $feeds = [
            new NetworkFeed(
                'dbip_country',
                'DB-IP IP to Country Lite',
                [
                    'https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.csv.gz',
                ],
                NetworkFeed::KIND_COUNTRY,
                [
                    'status' => 'permitted_with_attribution',
                    'note' => 'Creative Commons Attribution 4.0 International; credit DB-IP.com, link back on pages that show results. Monthly; downloads need no account.',
                    'source' => 'https://db-ip.com/db/lite.php',
                    'checked_on' => '2026-10-31',
                ],
                'IP Geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0.',
                604800,
                3024000, // 35 days: the file is monthly
                6480000, // 75 days
            ),
            new NetworkFeed(
                'iptoasn',
                'IPtoASN combined (IPv4 and IPv6)',
                ['https://iptoasn.com/data/ip2asn-combined.tsv.gz'],
                NetworkFeed::KIND_ASN,
                [
                    'status' => 'permitted',
                    'note' => 'Public Domain (PDDL 1.0) as stated on iptoasn.com; updated hourly. The country column is the registration country, not a geolocation.',
                    'source' => 'https://iptoasn.com/',
                    'checked_on' => '2026-10-31',
                ],
                '',
                86400,
                172800,
                1209600,
            ),
            new NetworkFeed(
                'bad_asn_list',
                'bad-asn-list (hosting, cloud and colocation ASNs)',
                ['https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv'],
                NetworkFeed::KIND_HOSTING_ASN_LIST,
                [
                    'status' => 'permitted_with_attribution',
                    'note' => 'MIT licence (Copyright (c) 2025 Brian Hamachek): keep the copyright and licence notice with copies. A single-maintainer list; ignored after a year.',
                    'source' => 'https://github.com/brianhama/bad-asn-list',
                    'checked_on' => '2026-10-31',
                ],
                'Contains the bad-asn-list by Brian Hamachek (MIT, https://github.com/brianhama/bad-asn-list).',
                86400,
                2592000,
                31536000,
            ),
        ];

        $out = [];
        foreach ($feeds as $feed) {
            $out[$feed->key] = $feed;
        }

        return $out;
    }
}

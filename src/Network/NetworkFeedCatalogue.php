<?php

declare(strict_types=1);

namespace DeviceId\Network;

use DeviceId\Signals\SmartSignals;

/**
 * The local datasets the package can load, with the licence finding for each (checked
 * 2026-10-31 against the publishers' own pages and the files themselves; re-check before
 * relying on it, terms change).
 *
 * ## The rule for this catalogue: no source that needs PUBLIC credit
 *
 * A credit on a public page would reveal a detection method. {@see NetworkFeed::isUsableWithout()}
 * refuses any feed that carries an attribution text or the status `public_credit_required`, and
 * {@see NetworkDatabase::attribution()} is therefore always empty. A copyright notice that only has to
 * travel with a copy of the data (the MIT list below) lives in `LICENSE-THIRD-PARTY.md`.
 *
 * ## Included (no account, no key, free for commercial use)
 *
 * - **sapics/ip-location-db `user-country`** (PDDL 1.0, "free use without attribution"): daily
 *   CSV `start,end,CC`, one file per address family. Compiled by the maintainer from RIR delegated
 *   statistics, Route Views / RIPE RIS routing data and public geofeeds (RFC 8805). It is a
 *   REGISTRATION-and-routing country, not a measurement of where the person sits: the maintainer
 *   measures 97.5 % agreement with GeoLite2 on IPv4 (2026-06-14), and the rule that reads it is
 *   built so that its errors only make it quieter ({@see SmartSignals::localeAgainstCountry()}).
 *   Two caveats stay with the maintainer's statement: the geofeeds "lack explicitly defined
 *   licenses" and the RIR input is "subject to the NRO License and respective RIR copyright
 *   statements".
 * - **IPtoASN combined** (Public Domain, PDDL 1.0): hourly TSV `start end ASN country name`. ASN
 *   and registered name drive {@see AsnClassifier}; the country column is the ASN's REGISTRATION
 *   country, kept only as the second opinion that makes the locale rule quieter, never as a
 *   geolocation.
 * - **bad-asn-list** (MIT, Brian Hamachek): about 740 ASNs of hosting, cloud and colocation
 *   providers, a CSV `ASN,Entity`. A single-maintainer list, so it only adds ASNs the name
 *   classifier missed, and it is ignored after a year. The MIT notice is in
 *   `LICENSE-THIRD-PARTY.md`.
 *
 * ## Deliberately NOT included
 *
 * - **DB-IP IP to Country / City / ASN Lite** (CC BY 4.0): DB-IP asks for a link back "on pages
 *   that display or use results from the database". That is a public credit. Removed 2026-10-31.
 * - **MaxMind GeoLite2**: needs an account and a licence key, requires attribution of the use,
 *   forbids disclosing the data to third parties and requires destroying superseded versions
 *   within 30 days. The PAID **MaxMind GeoIP Country** (USD 418 per year and legal entity) has no
 *   attribution clause in its licence documents and is the recommended accuracy upgrade: a host
 *   builds a {@see NetworkFacts} from its own copy (see the README). It is not fetched here.
 * - **ipverse/rir-ip** (CC0 1.0): pure registration country per RIR, "not intended for precise
 *   operational geolocation"; a possible alternative key, not wired.
 * - **RIPE NCC delegated files**: the RIPE NCC copyright statement limits use of its materials to
 *   private, non-commercial and research purposes unless authorised; whether the statistics files
 *   fall under it is unclear, so the package does not read them directly.
 * - **X4BNet/lists_vpn and IPLocate**: the generated lists are MIT but derive from the IPLocate
 *   database (CC BY-SA 4.0, share-alike).
 * - **A free list of VPN ASNs with a licence**: none was found. VPN detection is therefore the
 *   name classifier on the IPtoASN registered names.
 */
final class NetworkFeedCatalogue
{
    /**
     * @return array<string, NetworkFeed>
     */
    public static function defaults(): array
    {
        $feeds = [
            self::sapicsCountry('country_ipv4', 'sapics user-country (IPv4)', 'user-country-ipv4.csv'),
            self::sapicsCountry('country_ipv6', 'sapics user-country (IPv6)', 'user-country-ipv6.csv'),
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
                    'status' => 'permitted_with_notice',
                    'note' => 'MIT licence (Copyright (c) 2025 Brian Hamachek): the copyright and permission notice travels with copies (LICENSE-THIRD-PARTY.md); no public credit. A single-maintainer list; ignored after a year.',
                    'source' => 'https://github.com/brianhama/bad-asn-list',
                    'checked_on' => '2026-10-31',
                ],
                '',
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

    /**
     * One address family of the sapics `user-country` database. The raw file URL answers without
     * a redirect (a host fetcher that refuses redirects can use it); the release asset is the
     * maintainer's own distribution point since 2026-06-18 and answers with a redirect; the
     * jsDelivr mirror serves the same repository file.
     */
    private static function sapicsCountry(string $key, string $name, string $file): NetworkFeed
    {
        return new NetworkFeed(
            $key,
            $name,
            [
                'https://raw.githubusercontent.com/sapics/ip-location-db/main/user-country/'.$file,
                'https://cdn.jsdelivr.net/gh/sapics/ip-location-db@main/user-country/'.$file,
                'https://github.com/sapics/ip-location-db/releases/download/latest/'.$file,
            ],
            NetworkFeed::KIND_COUNTRY,
            [
                'status' => 'permitted',
                'note' => 'PDDL 1.0 per the project README ("free use without attribution"); daily. Inputs: RIR delegated statistics, Route Views and RIPE RIS, public geofeeds (the README says many lack explicit licences and the RIR data is subject to the NRO licence). Registration/routing country, not a measurement.',
                'source' => 'https://github.com/sapics/ip-location-db',
                'checked_on' => '2026-10-31',
            ],
            '',
            86400,
            172800,
            1209600,
        );
    }
}

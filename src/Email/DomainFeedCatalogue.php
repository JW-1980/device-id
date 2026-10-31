<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * The e-mail-domain lists the package can load (checked 2026-10-31 against the files and licence
 * texts themselves; re-check, terms change). None needs a public credit; the MIT notices are in
 * `LICENSE-THIRD-PARTY.md`.
 *
 * - **disposable-email-domains** (CC0 1.0): about 10,000 domains, curated; the precise list.
 * - **disposable/disposable-email-domains `domains_mx.txt`** (MIT): about 52,000 aggregated
 *   disposable domains that still have a valid MX or A record (a domain that cannot receive mail
 *   is no use to a person signing up), refreshed daily by the maintainer.
 * - **disposable/static-disposable-lists `mailservices.json`** (MIT): 325 mail providers with
 *   their type and cost; yields the free mailbox providers (Gmail, Outlook, Yahoo, iCloud, GMX...)
 *   and the alias and forwarding services (Hide My Email, SimpleLogin, Firefox Relay, DuckDuckGo).
 *
 * ## Deliberately NOT included
 *
 * - The **strict** list of disposable/disposable: it adds freemail with CAPTCHA-only signup
 *   (outlook.com, hotmail.com); as a signal it would flag a large honest population.
 * - **Kikobeats/free-email-domains** (MIT): one list that mixes free providers with disposable
 *   ones, so it cannot tell the two apart.
 */
final class DomainFeedCatalogue
{
    /**
     * @return array<string, DomainFeed>
     */
    public static function defaults(): array
    {
        $checked = '2026-10-31';
        $feeds = [
            new DomainFeed(
                'disposable_email_domains',
                'disposable-email-domains (blocklist)',
                [
                    'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf',
                    'https://cdn.jsdelivr.net/gh/disposable-email-domains/disposable-email-domains@main/disposable_email_blocklist.conf',
                ],
                DomainFeed::FORMAT_LINES,
                [DomainFeed::DISPOSABLE],
                ['status' => 'permitted', 'note' => 'CC0 1.0 (LICENSE.txt): "You can copy, modify, distribute and perform the work, even for commercial purposes, all without asking permission".', 'source' => 'https://github.com/disposable-email-domains/disposable-email-domains', 'checked_on' => $checked],
            ),
            new DomainFeed(
                'disposable_mx',
                'disposable/disposable-email-domains (domains with valid DNS)',
                [
                    'https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains_mx.txt',
                    'https://disposable.github.io/disposable-email-domains/domains_mx.txt',
                ],
                DomainFeed::FORMAT_LINES,
                [DomainFeed::DISPOSABLE],
                ['status' => 'permitted_with_notice', 'note' => 'MIT (Copyright (c) 2017 Andrei Simionescu, Stefan Meinecke, greenSec GmbH): the notice travels with copies (LICENSE-THIRD-PARTY.md); no public credit.', 'source' => 'https://github.com/disposable/disposable-email-domains', 'checked_on' => $checked],
            ),
            new DomainFeed(
                'mail_services',
                'disposable/static-disposable-lists mailservices.json',
                [
                    'https://raw.githubusercontent.com/disposable/static-disposable-lists/master/mailservices.json',
                    'https://cdn.jsdelivr.net/gh/disposable/static-disposable-lists@master/mailservices.json',
                ],
                DomainFeed::FORMAT_MAILSERVICES,
                [DomainFeed::FREE, DomainFeed::FORWARDING],
                ['status' => 'permitted_with_notice', 'note' => 'MIT (Copyright (c) 2022 disposable): the notice travels with copies (LICENSE-THIRD-PARTY.md); no public credit.', 'source' => 'https://github.com/disposable/static-disposable-lists', 'checked_on' => $checked],
            ),
        ];

        $out = [];
        foreach ($feeds as $feed) {
            $out[$feed->key] = $feed;
        }

        return $out;
    }
}

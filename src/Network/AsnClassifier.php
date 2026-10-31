<?php

declare(strict_types=1);

namespace DeviceId\Network;

/**
 * Classifies an autonomous system from the name its operator registered, so the category needs
 * no licensed list: the names come from the same public-domain IPtoASN file as the ranges.
 *
 * ## Why keywords, and what they cost
 *
 * `vpn` means a VPN service ("LITE-VPN-AS", "SKYVPN"); `hosting` means the name says the network
 * sells hosting, colocation or server capacity. A name is the operator's own description, so a
 * match is real evidence about the network and not a guess about a person. It under-detects (a
 * VPN or hosting company that names itself after a brand matches nothing) and it can over-detect
 * (an ISP that also sells hosting): both errors are why the result is only ever a soft fact.
 * The hosting words are matched as whole words ("colo" does not match inside "Colorado"); "vpn"
 * is matched anywhere because VPN brands glue it to their name (SKYVPN).
 */
final class AsnClassifier
{
    private const VPN = '/vpn|\bvirtual private network\b/i';

    private const HOSTING = '/\b(hosting|hoster|datacenters?|data ?cent(?:er|re)s?|colocation|colo|vps|dedicated servers?|web ?hosting|cloud (?:hosting|computing|infrastructure|servers?))\b/i';

    /**
     * @return string|null {@see NetworkFacts::CATEGORY_VPN}, {@see NetworkFacts::CATEGORY_HOSTING} or null
     */
    public static function classify(string $description): ?string
    {
        if (preg_match(self::VPN, $description) === 1) {
            return NetworkFacts::CATEGORY_VPN;
        }
        if (preg_match(self::HOSTING, $description) === 1) {
            return NetworkFacts::CATEGORY_HOSTING;
        }

        return null;
    }
}

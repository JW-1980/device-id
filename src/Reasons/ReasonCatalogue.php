<?php

declare(strict_types=1);

namespace DeviceId\Reasons;

use DeviceId\CheckRegistry;
use DeviceId\Support\Verdict;

/**
 * Every reason the engine and its soft signals can give, with its DIRECTION: does it raise the
 * risk of a visit or lower it. minFraud expresses the same thing with a multiplier above or below
 * one; here the direction is explicit and the weights stay additive and reconstructible.
 *
 * ## Where the codes come from
 *
 * - **Rule codes** ({@see CheckRegistry}): every contradiction raises. A contradiction is never
 *   evidence of honesty.
 * - **Soft reasons** ({@see SOFT}): facts the engine does not score by itself (e-mail, account
 *   novelty, velocity distinct counts, network history, network facts). Each raises, except the
 *   explicit de-escalators (`acct_known_device`, `acct_known_country`, `history_not_abuse`,
 *   `allow_listed`, and a `model_adjustment` with a negative weight).
 * - Context that is NOT a reason, because it is not evidence of abuse by itself: `email_free`,
 *   `email_tagged`, `sig_private_mode` (see {@see CONTEXT_ONLY}).
 *
 * A test pins that every optional model feature is either a reason or listed as context only, so
 * a new feature cannot reach the explanations without a direction.
 *
 * ## Use
 *
 * {@see explain()} turns a verdict, the model's opinion and the soft features of a visit into the
 * list a review screen renders, identically in every host.
 */
final class ReasonCatalogue
{
    public const RAISES = 'raises';

    public const LOWERS = 'lowers';

    /**
     * Soft reason code => [direction, family, description].
     *
     * @var array<string, array{string, string, string}>
     */
    private const SOFT = [
        // --- e-mail ---------------------------------------------------------
        'email_disposable' => [self::RAISES, 'email', 'The e-mail domain is on a disposable-address list. Never a block on its own: people use disposable addresses to avoid spam.'],
        'email_forwarding_alias' => [self::RAISES, 'email', 'The address is a forwarding or alias service (Hide My Email, SimpleLogin, Firefox Relay). Weak: privacy-minded people use them.'],
        'email_domain_no_mx' => [self::RAISES, 'email', 'The e-mail domain cannot receive mail (confirmed by two DNS checks). A validation problem first, abuse second.'],
        'email_generated' => [self::RAISES, 'email', 'The local part looks machine-generated or random (several independent signs). Weak: some people have such addresses.'],
        'email_multiple_aliases' => [self::RAISES, 'email', 'Several differently written addresses reach one mailbox (name+1@, name+2@, n.a.m.e@) in the window.'],
        'email_pattern_family' => [self::RAISES, 'email', 'Several addresses share a letter stem and differ in trailing digits (name123, name124) in the window.'],
        // --- account novelty --------------------------------------------------
        'acct_new_device' => [self::RAISES, 'novelty', 'The account is used from a device it has not been seen on (never raised on the first observation).'],
        'acct_new_country' => [self::RAISES, 'novelty', 'The account is used from a country it has not been seen in.'],
        'acct_new_asn' => [self::RAISES, 'novelty', 'The account is used from a network (ASN) it has not been seen on. Weak: mobile carriers, new homes.'],
        'acct_new_language' => [self::RAISES, 'novelty', 'The account is used with a browser language it has not shown before.'],
        'acct_new_os' => [self::RAISES, 'novelty', 'The account is used from an operating system it has not shown before.'],
        'acct_known_device' => [self::LOWERS, 'novelty', 'The account has been seen on this device before.'],
        'acct_known_country' => [self::LOWERS, 'novelty', 'The account has been seen in this country before.'],
        // --- velocity ----------------------------------------------------------
        'vel_burst' => [self::RAISES, 'velocity', 'Sign-ups or sign-ins from one device or network reached the burst limit in the window.'],
        'vel_impossible_travel' => [self::RAISES, 'velocity', 'Two sessions of one account are too far apart for the time between them.'],
        'vel_accounts_per_device_1h' => [self::RAISES, 'velocity', 'Many distinct accounts used one device within an hour.'],
        'vel_accounts_per_device_24h' => [self::RAISES, 'velocity', 'Many distinct accounts used one device within a day.'],
        'vel_accounts_per_device_7d' => [self::RAISES, 'velocity', 'Many distinct accounts used one device within a week.'],
        'vel_devices_per_account_1h' => [self::RAISES, 'velocity', 'One account was used from many distinct devices within an hour.'],
        'vel_devices_per_account_24h' => [self::RAISES, 'velocity', 'One account was used from many distinct devices within a day.'],
        'vel_devices_per_account_7d' => [self::RAISES, 'velocity', 'One account was used from many distinct devices within a week.'],
        'vel_emails_per_network_1h' => [self::RAISES, 'velocity', 'Many distinct e-mail addresses were used from one network within an hour. A shared network (campus, office) does this honestly.'],
        'vel_emails_per_network_24h' => [self::RAISES, 'velocity', 'Many distinct e-mail addresses were used from one network within a day. A shared network does this honestly.'],
        'vel_emails_per_network_7d' => [self::RAISES, 'velocity', 'Many distinct e-mail addresses were used from one network within a week. A shared network does this honestly.'],
        // --- network ------------------------------------------------------------
        'net_hosting' => [self::RAISES, 'network', 'The address belongs to a hosting, cloud or colocation network.'],
        'net_vpn' => [self::RAISES, 'network', 'The address belongs to a network whose registered name says it is a VPN service.'],
        'net_tor_exit' => [self::RAISES, 'network', 'The address is a Tor exit.'],
        'net_history_bad' => [self::RAISES, 'network', 'A large share of this network\'s devices were labelled abuse by your own reviewers (k-floor applies).'],
        'rep_datacenter' => [self::RAISES, 'network', 'The address is inside a published cloud range.'],
        'rep_tor_exit' => [self::RAISES, 'network', 'The address is on the Tor exit list.'],
        'rep_abuse_listed' => [self::RAISES, 'network', 'The address is on an abuse list you supplied.'],
        'sig_locale_disagreements' => [self::RAISES, 'environment', 'The time zone and the languages disagree with the IP address\'s country.'],
        'sig_vm_gpu' => [self::RAISES, 'environment', 'The GPU is a hypervisor\'s virtual GPU.'],
        'sig_vm_screen' => [self::RAISES, 'environment', 'The screen has the default size of a hypervisor.'],
        'sig_software_gpu' => [self::RAISES, 'environment', 'Rendering is done by a software rasteriser.'],
        'sig_emulator' => [self::RAISES, 'environment', 'The device is an Android emulator.'],
        // --- de-escalators from the host's own record -----------------------------
        'history_not_abuse' => [self::LOWERS, 'feedback', 'A reviewer of yours marked this device not_abuse.'],
        'allow_listed' => [self::LOWERS, 'allowance', 'The traffic is allowed (verified crawler, uptime monitor or operator allowlist).'],
    ];

    /** Optional model features that are context, not evidence of abuse, so they carry no reason. */
    public const CONTEXT_ONLY = ['email_free', 'email_tagged', 'sig_private_mode'];

    /**
     * @return list<string> every code with a direction
     */
    public static function codes(): array
    {
        return [...CheckRegistry::codes(), 'model_adjustment', ...array_keys(self::SOFT)];
    }

    /**
     * RAISES or LOWERS, or null for an unknown code. A positive `model_adjustment` raises; use
     * {@see directionOfDisagreement()} for one with its weight.
     */
    public static function directionOf(string $code): ?string
    {
        if (isset(self::SOFT[$code])) {
            return self::SOFT[$code][0];
        }

        return CheckRegistry::isKnown($code) || $code === 'model_adjustment' || str_starts_with($code, 'transport_') ? self::RAISES : null;
    }

    /**
     * @param  array{code: string, weight: int}  $disagreement
     */
    public static function directionOfDisagreement(array $disagreement): ?string
    {
        if ($disagreement['code'] === 'model_adjustment') {
            return $disagreement['weight'] < 0 ? self::LOWERS : self::RAISES;
        }

        return self::directionOf($disagreement['code']);
    }

    /**
     * @return array{code: string, direction: string, family: string, description: string}|null
     */
    public static function describe(string $code): ?array
    {
        if (isset(self::SOFT[$code])) {
            [$direction, $family, $description] = self::SOFT[$code];

            return ['code' => $code, 'direction' => $direction, 'family' => $family, 'description' => $description];
        }
        if (CheckRegistry::isKnown($code)) {
            return ['code' => $code, 'direction' => self::RAISES, 'family' => CheckRegistry::familyOf($code) ?? 'unknown', 'description' => CheckRegistry::descriptionOf($code) ?? ''];
        }
        if ($code === 'model_adjustment') {
            return ['code' => $code, 'direction' => self::RAISES, 'family' => 'model', 'description' => 'The statistical model adjusted the score; the sign of the weight is the direction.'];
        }

        return null;
    }

    /**
     * The whole catalogue, for a documentation page or an admin screen.
     *
     * @return array<string, array{code: string, direction: string, family: string, description: string}>
     */
    public static function all(): array
    {
        $out = [];
        foreach (self::codes() as $code) {
            $entry = self::describe($code);
            if ($entry !== null) {
                $out[$code] = $entry;
            }
        }

        return $out;
    }

    /**
     * The explanation of one visit: the disagreements (a `model_adjustment` with a negative weight
     * lowers), the soft features that hold and an allowance, each with its direction. Raising reasons come first, by
     * weight where there is one, then lowering ones; codes the catalogue does not know are kept as
     * `unlisted` raising entries (a rule added without a description must still be visible).
     *
     * @param  array<string, float>  $softFeatures  reputation, network, signals, velocity, e-mail, novelty features that hold
     * @param  list<string>  $extraCodes  other soft reason codes the host determined (`email_multiple_aliases`, `history_not_abuse`, `acct_known_device`...)
     * @return list<array{code: string, direction: string, family: string, description: string, weight: int|null}>
     */
    public static function explain(Verdict $verdict, array $softFeatures = [], array $extraCodes = []): array
    {
        $entries = [];
        foreach ($verdict->disagreements as $disagreement) {
            $code = $disagreement['code'];
            $direction = self::directionOfDisagreement($disagreement) ?? self::RAISES;
            $info = self::describe($code) ?? ['code' => $code, 'direction' => $direction, 'family' => str_starts_with($code, 'transport_') ? 'transport' : 'unlisted', 'description' => $disagreement['detail']];
            $entries[$code] = ['code' => $code, 'direction' => $direction, 'family' => $info['family'], 'description' => $info['description'], 'weight' => $disagreement['weight']];
        }
        if ($verdict->allowance !== null) {
            $entries['allow_listed'] = self::entry('allow_listed', null);
        }
        foreach ([...array_keys($softFeatures), ...$extraCodes] as $code) {
            if (isset(self::SOFT[$code]) && ! isset($entries[$code])) {
                $entries[$code] = self::entry($code, null);
            }
        }

        $list = array_values($entries);
        usort($list, static function (array $a, array $b): int {
            if ($a['direction'] !== $b['direction']) {
                return $a['direction'] === self::RAISES ? -1 : 1;
            }

            return [abs($b['weight'] ?? 0), $a['code']] <=> [abs($a['weight'] ?? 0), $b['code']];
        });

        return $list;
    }

    /**
     * @return array{code: string, direction: string, family: string, description: string, weight: int|null}
     */
    private static function entry(string $code, ?int $weight): array
    {
        [$direction, $family, $description] = self::SOFT[$code];

        return ['code' => $code, 'direction' => $direction, 'family' => $family, 'description' => $description, 'weight' => $weight];
    }

    /**
     * Whether an optional model feature has a reason code or is declared context only.
     */
    public static function coversFeature(string $feature): bool
    {
        return isset(self::SOFT[$feature]) || in_array($feature, self::CONTEXT_ONLY, true);
    }
}

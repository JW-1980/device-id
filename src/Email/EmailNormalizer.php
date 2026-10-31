<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * The canonical form of an e-mail address for duplicate detection, so `naam+1@gmail.com`,
 * `n.a.a.m@googlemail.com` and `Naam@Gmail.com` count as one mailbox. Ported from WelZoLekker's
 * `EmailNormalizer` (read-only reference) as pure functions, with the parsing made strict.
 *
 * Rules: lower-cased and trimmed; a `+tag` (sub-address) is removed for every provider, because
 * almost every provider delivers `name+anything` to `name`; dots in the local part are removed
 * only for the providers that ignore them ({@see GMAIL_DOMAINS}), and `googlemail.com` becomes
 * `gmail.com`. Accepted limit: at the rare provider where `+` is part of a real, distinct mailbox
 * name, two people would be treated as one address; that only flags or links their accounts, it
 * never merges them.
 *
 * Syntax is checked only as far as duplicate detection and domain lookups need: exactly one `@`
 * outside quotes is not attempted, a quoted local part is refused (null), lengths follow RFC 5321
 * (local part 64, domain 253, total 254) and the domain must have at least two labels. An address
 * that fails is NOT an abuse signal: the host's own validation reports it to the person.
 *
 * The normalised address is never stored: keep {@see hash()}, a keyed HMAC-SHA256 that is only
 * compared for equality.
 */
final class EmailNormalizer
{
    /** Providers that deliver mail regardless of dots in the local part. */
    public const GMAIL_DOMAINS = ['gmail.com', 'googlemail.com'];

    public static function parse(string $email): ?ParsedEmail
    {
        $email = mb_strtolower(trim($email));
        if ($email === '' || strlen($email) > 254 || str_contains($email, '"') || preg_match('/[\s<>(),;:\\\\\[\]]/', $email) === 1) {
            return null;
        }
        $at = strrpos($email, '@');
        if ($at === false || $at === 0 || substr_count($email, '@') !== 1) {
            return null;
        }

        $local = substr($email, 0, $at);
        $domain = rtrim(substr($email, $at + 1), '.');
        if (strlen($local) > 64) {
            return null;
        }
        if (function_exists('idn_to_ascii') && preg_match('/[^\x00-\x7f]/', $domain) === 1) {
            $ascii = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            $domain = is_string($ascii) ? $ascii : $domain;
        }
        if (strlen($domain) > 253 || preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $domain) !== 1) {
            return null;
        }

        $mailbox = $local;
        $tag = null;
        $plus = strpos($local, '+');
        if ($plus !== false && $plus > 0) {
            $mailbox = substr($local, 0, $plus);
            $tag = substr($local, $plus + 1);
        }

        $canonicalDomain = $domain;
        if (in_array($domain, self::GMAIL_DOMAINS, true)) {
            $mailbox = str_replace('.', '', $mailbox);
            $canonicalDomain = 'gmail.com';
        }

        return new ParsedEmail($local, $domain, $mailbox, $tag === '' ? null : $tag, $canonicalDomain);
    }

    /**
     * The canonical address, or null when the input is not an address this class can read.
     */
    public static function canonical(string $email): ?string
    {
        return self::parse($email)?->canonical();
    }

    /**
     * The keyed hash a host may store to find the same mailbox again: HMAC-SHA256 of the canonical
     * address under a secret of its own purpose (hex, 64 characters). Null for an unreadable address.
     */
    public static function hash(string $email, string $secret): ?string
    {
        if (strlen($secret) < 32) {
            throw new \InvalidArgumentException('the e-mail hash secret must be at least 32 characters');
        }
        $canonical = self::canonical($email);

        return $canonical === null ? null : hash_hmac('sha256', $canonical, $secret);
    }

    /**
     * How many distinct typed addresses reach each mailbox, as counts only (no address leaves):
     * `multiple_aliases_per_email`. `test+1@`, `test+2@` and `t.e.s.t@gmail.com` are three addresses
     * to one mailbox.
     *
     * @param  list<string>  $addresses  raw addresses seen in the window
     * @return array{mailboxes: int, max_aliases: int}
     */
    public static function aliasSpread(array $addresses): array
    {
        $perMailbox = [];
        foreach ($addresses as $address) {
            $parsed = is_string($address) ? self::parse($address) : null;
            if ($parsed !== null) {
                $perMailbox[$parsed->canonical()][$parsed->local.'@'.$parsed->domain] = true;
            }
        }

        return ['mailboxes' => count($perMailbox), 'max_aliases' => $perMailbox === [] ? 0 : max(array_map('count', $perMailbox))];
    }
}

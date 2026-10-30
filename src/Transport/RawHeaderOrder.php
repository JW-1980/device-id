<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Transport;

/**
 * The outcome of trying to recover the client's HTTP header order.
 *
 * A value object rather than a nullable array because the failure carries
 * information: an operator reading the security screen needs to know whether
 * order is unavailable because the proxy is not configured, or because it is
 * configured and the signature did not verify. Those are different problems with
 * different fixes, and collapsing both to null would hide the second one - which
 * is the one that could mean somebody is forging the header.
 *
 * @see RawHeaderCapture for why recovery is needed and why it must be signed
 */
final class RawHeaderOrder
{
    /**
     * @param  list<string>  $order  lower-cased header names, in wire order
     */
    private function __construct(
        public readonly bool $available,
        public readonly array $order,
        public readonly string $reason,
    ) {}

    /**
     * @param  list<string>  $order
     */
    public static function recovered(array $order, string $reason = 'recovered from the proxy'): self
    {
        return new self(true, $order, $reason);
    }

    public static function unavailable(string $reason): self
    {
        return new self(false, [], $reason);
    }

    /**
     * Turn the recovered order into the name/value pairs TransportIntegrity expects.
     *
     * Values come from the request's own header bag, which is case-insensitive.
     * Only the *order* came from the proxy, so a forged order cannot forge a value -
     * and the signature check upstream means the order itself is trusted too.
     *
     * @return list<array{0: string, 1: string}>
     */
    /**
     * @param  array<array-key, mixed>  $headers
     * @return list<array{0: string, 1: string}>
     */
    public function pairs(array $headers): array
    {
        if (! $this->available) {
            return [];
        }

        $bag = $headers;
        $pairs = [];

        foreach ($this->order as $name) {
            if (! array_key_exists($name, $bag)) {
                // The proxy and PHP disagree about which headers exist. Returning a
                // partial order would be worse than returning none: a truncated
                // order is not a weaker version of the signal, it is a different and
                // wrong one, and it would quietly poison the engine profile table.
                return [];
            }
            foreach (is_array($bag[$name] ?? null) ? $bag[$name] : [] as $value) {
                // `is_string`, not a bare cast and not `is_scalar`. A header value arriving as an
                // array casts to the string "Array" with a notice, and a witness built from
                // "Array" can never match a real signature — so the failure would be silent,
                // and it would present as tampering on every request that carried it.
                //
                // `is_scalar` was tried first and is weaker than it looks: it also admits
                // bool/int/float, so a boolean header would be stringified to "1" and a
                // numeric one to its digits — a different route to the same poisoning.
                // Accepting only a real string removes the whole class. PHPStan flagged the
                // earlier `(string) $value` as a useless cast, which is what exposed it.
                //
                // This lived only in the PORTED copy at first, which made it a hand-edit the
                // generator of that time could not reproduce: regenerating reverted it
                // silently. Since 2026-10-21 this package is the only copy and nothing
                // regenerates it.
                $pairs[] = [$name, is_string($value) ? $value : ''];
            }
        }

        return $pairs;
    }
}

/**
 * Recovers the order of the request's header names.
 *
 * ## Two sources, in this order
 *
 * 1. **A signed order from the edge** (`X-Raw-Header-Order` + `X-Raw-Header-Sig`), when
 *    `raw_header_secret` is configured and the edge sent both. This is the override: it
 *    is the only source when something other than the FastCGI nginx terminates the
 *    client connection, and it keeps the original case. A signed order that does not
 *    verify is REFUSED (unavailable, with the reason) rather than replaced by the second
 *    source: a forgery is evidence, and an operator needs to see it.
 * 2. **PHP-FPM's own parameter order** (`fastcgi_header_order`, on by default). nginx
 *    emits the client's headers to FastCGI in arrival order and PHP-FPM builds
 *    `$_SERVER` in exactly the REVERSE order, so reversing the `HTTP_*` keys recovers the
 *    wire order. Measured (round-1 webserver review WS-7, `order-truth.mjs`, nginx 1.24 +
 *    PHP 8.3.6 FPM; re-measured round 2, WS2-4): identical to the true wire order for
 *    HTTP/1.1 (60 of 60 crafted orders, all engines); for HTTP/2 and HTTP/3 identical
 *    EXCEPT that nginx re-assembles the cookie crumbs and appends `cookie` after every
 *    other header, plus a leading `host` (synthesised by nginx from `:authority`) that is
 *    removed here. A JA4H built on this order is unaffected (section b excludes Cookie);
 *    an order-profile table is not. Limits, stated rather than hidden:
 *    - it is the order of the hop that feeds PHP-FPM. Behind another proxy it is that
 *      proxy's order — deterministic, but not the client's — so a deployment with an
 *      edge in front of the pod nginx should turn the switch off or use source 1;
 *    - it relies on a php-src implementation detail (FastCGI params hash prepend),
 *      verified on PHP 8.3.6 FPM only, and is used under the `fpm-fcgi` SAPI only;
 *    - case is lost (`HTTP_SEC_CH_UA`), so names are lower-case; nginx drops names with
 *      underscores and keeps one entry for a repeated header.
 *    Header names the edge or the nginx configuration inject (`X-Ja4*`, `X-Client-Proto`,
 *    `X-Raw-Header-*`, `CF-Ja4`, `SSL-Ja4`, the httpoxy `Proxy` param) are left out:
 *    `Ja4Reader` removes the edge headers from the request after reading them, and an
 *    order naming a header the bag no longer has is discarded by `RawHeaderOrder::pairs()`.
 *
 * ## Why the forwarded value must be signed
 *
 * `X-Raw-Header-Order` is a request header, so a client can send it. An attacker who
 * forged it to match a known engine profile would pass the very check this exists to
 * support. The edge therefore also emits an HMAC of the order under a secret only the
 * proxy and this application know. **Without `raw_header_secret` the header is ignored
 * entirely** and only source 2 can supply an order. The FastCGI order cannot be forged
 * that way: it is built by nginx and PHP-FPM from what arrived on the wire.
 *
 * ## A measured caveat about the research captures
 *
 * The header order in `research/fingerprinting/captures` is NOT a reliable reference.
 * Playwright's synchronous `request.headers()` omits the whole `Sec-Fetch-*` family,
 * and `await request.allHeaders()` intermittently falls back to it, so most captured
 * requests are incomplete. Do not derive an engine profile table from those files.
 */

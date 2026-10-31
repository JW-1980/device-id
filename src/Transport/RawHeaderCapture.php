<?php

declare(strict_types=1);

namespace DeviceId\Transport;

use DeviceId\Support\Config;

final class RawHeaderCapture
{
    /**
     * One header, looked up case-insensitively.
     *
     * Symfony's `HeaderBag::get()` did this. Taking a plain array means doing it
     * here, and every SAPI in use lower-cases header names on the wire, so
     * comparing lower-cased changes nothing.
     *
     * @param  array<array-key, mixed>  $headers
     */
    private static function header(array $headers, string $name): ?string
    {
        $wanted = strtolower($name);
        foreach ($headers as $key => $value) {
            if (strtolower((string) $key) !== $wanted) {
                continue;
            }

            $first = is_array($value) ? ($value[0] ?? null) : $value;

            return is_string($first) ? $first : null;
        }

        return null;
    }

    /** The header the nginx snippet sets. */
    public const ORDER_HEADER = 'X-Raw-Header-Order';

    /** The companion signature the nginx snippet sets. */
    public const SIGNATURE_HEADER = 'X-Raw-Header-Sig';

    /** Defence in depth: a real engine order is nowhere near this long. */
    private const MAX_ORDER_LENGTH = 4096;

    /** The only server API whose `$_SERVER` order was measured to be the reversed wire order. */
    public const FASTCGI_SAPI = 'fpm-fcgi';

    /** A real browser sends 10-25 headers; this bounds the work on a hostile request. */
    private const MAX_FASTCGI_NAMES = 128;

    /**
     * Names injected by the edge or by the nginx config rather than sent by the client,
     * lower-cased. `proxy` is the httpoxy mitigation (`fastcgi_param HTTP_PROXY ""`).
     */
    private const INJECTED_NAMES = [
        'x-ja4', 'x-ja4-r', 'x-ja4-sig', 'x-ja4-ts', 'x-ja4-request-id', 'x-ja4-sections',
        'cf-ja4', 'ssl-ja4', 'x-client-proto', 'x-raw-header-order', 'x-raw-header-sig', 'proxy',
    ];

    private readonly string $sapi;

    /**
     * Stateless. The recovered order travels on the returned RawHeaderOrder, not on this
     * object. `$sapi` exists for tests; the container builds this with the real one.
     */
    public function __construct(?string $sapi = null)
    {
        $this->sapi = $sapi ?? PHP_SAPI;
    }

    /**
     * @param  array<array-key, mixed>  $headers
     * @param  array<array-key, mixed>  $server  `$_SERVER`-shaped; see fromFastCgi()
     */
    public function capture(array $headers, array $server = []): RawHeaderOrder
    {
        $raw = self::header($headers, self::ORDER_HEADER);
        $signature = self::header($headers, self::SIGNATURE_HEADER);

        $secret = Config::raw('transport_integrity.raw_header_secret');
        $secretConfigured = is_string($secret) && $secret !== '';
        $signedOrderSent = is_string($raw) && $raw !== '' && is_string($signature) && $signature !== '';

        if ($secretConfigured && $signedOrderSent) {
            return $this->verifySigned($raw, $signature, $secret);
        }

        $fastCgi = $this->fromFastCgi($server);
        if ($fastCgi->available) {
            return $fastCgi;
        }

        // Neither source: say why both failed, so an operator can tell "no edge and not
        // FPM" from "edge configured but silent".
        $signedReason = $secretConfigured
            ? 'the proxy did not forward raw header order'
            : 'raw_header_secret is not configured, so a forwarded order is not trusted';

        return RawHeaderOrder::unavailable($signedReason.'; '.$fastCgi->reason);
    }

    /**
     * The order PHP-FPM received the `HTTP_*` parameters in, reversed back to wire order.
     *
     * Framework-free (a plain `$_SERVER`-shaped array), so the standalone package runs it
     * unchanged.
     *
     * @param  array<array-key, mixed>  $server
     */
    public function fromFastCgi(array $server): RawHeaderOrder
    {
        if (Config::raw('transport_integrity.fastcgi_header_order', true) !== true) {
            return RawHeaderOrder::unavailable('fastcgi_header_order is switched off');
        }

        if ($this->sapi !== self::FASTCGI_SAPI) {
            return RawHeaderOrder::unavailable(
                'the server API is '.$this->sapi.', not '.self::FASTCGI_SAPI.', so parameter order is not wire order'
            );
        }

        $names = [];
        foreach (array_reverse(array_keys($server)) as $key) {
            if (! is_string($key) || ! str_starts_with($key, 'HTTP_')) {
                continue;
            }

            $name = strtolower(str_replace('_', '-', substr($key, 5)));
            if ($name === '' || in_array($name, self::INJECTED_NAMES, true)) {
                continue;
            }

            if (preg_match('/^[!#$%&\'*+.^_`|~0-9a-z-]+$/', $name) !== 1) {
                return RawHeaderOrder::unavailable('a FastCGI header parameter is not a valid HTTP field name');
            }

            $names[] = $name;

            if (count($names) > self::MAX_FASTCGI_NAMES) {
                return RawHeaderOrder::unavailable('the request carried more header parameters than any browser sends');
            }
        }

        // nginx synthesises `Host` from `:authority` for HTTP/2 and HTTP/3 and emits it
        // FIRST; a browser's own order does not start with it. The protocol is read from
        // non-`HTTP_` params, which a client cannot set: `CLIENT_PROTOCOL` when the
        // deployment forwards it, else nginx's standard `SERVER_PROTOCOL`.
        $protocol = $server['CLIENT_PROTOCOL'] ?? $server['SERVER_PROTOCOL'] ?? null;
        if (in_array($protocol, ['HTTP/2.0', 'HTTP/3.0'], true) && ($names[0] ?? null) === 'host') {
            array_shift($names);
        }

        if ($names === []) {
            return RawHeaderOrder::unavailable('the FastCGI parameters carried no client headers');
        }

        return RawHeaderOrder::recovered($names, 'recovered from the FastCGI parameter order');
    }

    private function verifySigned(string $raw, string $signature, string $secret): RawHeaderOrder
    {
        if (strlen($raw) > self::MAX_ORDER_LENGTH) {
            return RawHeaderOrder::unavailable('forwarded header order exceeded the length limit');
        }

        if (! hash_equals($this->sign($raw, $secret), strtolower($signature))) {
            // A client can send both headers. Only something that knows the secret can
            // produce a matching signature, so a mismatch means the order did not come
            // from our proxy and must not be believed. This is the branch that matters
            // most: it is the one that would be a vulnerability rather than a gap.
            return RawHeaderOrder::unavailable('forwarded header order failed signature verification');
        }

        $names = [];
        foreach (explode('|', $raw) as $candidate) {
            $name = strtolower(trim($candidate));

            if ($name === '') {
                continue;
            }

            // Every entry must be a syntactically valid HTTP field name (RFC 9110
            // §5.6.2 `token`).
            //
            // Without this, anything at all could appear in the order witness — and
            // the order witness is what JA4H section `b` and any future engine
            // profile table consume. An entry with a space or a comma in it is not
            // a header name, so accepting one means the signal carries strings that
            // no browser can have sent. That is a correctness bug even when the
            // signature is valid, and it is the difference between "the order of the
            // headers" and "whatever the proxy passed along".
            //
            // A name failing this is a proxy misconfiguration, so the whole order is
            // discarded rather than the bad entry being dropped: a partial order is
            // a *different* signal, not a weaker one.
            if (preg_match('/^[!#$%&\'*+.^_`|~0-9a-z-]+$/', $name) !== 1) {
                return RawHeaderOrder::unavailable(
                    'forwarded header order contained a name that is not a valid HTTP field name'
                );
            }

            $names[] = $name;
        }

        if ($names === []) {
            return RawHeaderOrder::unavailable('forwarded header order was empty after parsing');
        }

        return RawHeaderOrder::recovered($names);
    }

    /**
     * The shared signature scheme: HMAC-SHA256 over the raw order string, keyed with the
     * configured secret, lowercase hex, and NOT truncated.
     *
     * Untruncated, and that is deliberate. Both nginx examples emit a full digest —
     * `hmac.new(secret, "sha256"):final(value)` — and `hash_equals()` compares length
     * first and returns false when the two differ. This method used to `substr(...)` the
     * result to 32 hex characters, which no example file ever did, so every signature a
     * real edge produced was rejected as a mismatch: the wire-order control was
     * permanently inert, reporting a plausible reason, with the suite green because the
     * tests sign and verify with PHP on both sides and never execute the snippet.
     *
     * A 64-character hex value is unremarkable in a header, and the full digest is
     * strictly more than the 128 bits the truncation was buying — so nothing is lost by
     * matching the edge.
     *
     * `Ja4Reader::sign()` is the same two lines and must stay so. They are the only two
     * signers an edge snippet has to agree with, and a difference between them is a
     * control that silently does nothing. The examples are the third party:
     * docker/nginx/conf.d/10-raw-headers.conf.example and 20-ja4.conf.example.
     */
    public function sign(string $rawOrder, string $secret): string
    {
        return hash_hmac('sha256', $rawOrder, $secret);
    }
}

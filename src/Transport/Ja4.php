<?php

declare(strict_types=1);

namespace DeviceId\Transport;

/**
 * A JA4 TLS ClientHello fingerprint, as computed at the edge.
 *
 * ## Why PHP cannot compute this
 *
 * JA4 is derived from the raw cipher-suite list, the extension types *in order*, the ALPN
 * list and the signature-algorithm list — all of which live inside the ClientHello, below
 * anything PHP's OpenSSL bindings expose. A PHP implementation could not be written, only
 * mocked. So JA4 is computed by the TLS terminator and supplied to the application, which
 * is why this class is a parser and a validator for a value somebody else computed.
 *
 * That creates a trust problem — a client could simply send the header — and it is solved
 * exactly as `RawHeaderCapture` solves it: the edge SIGNS the value, and an unsigned or
 * unverifiable one is discarded rather than believed. See `Ja4Capture`.
 *
 * ## The format
 *
 *     t13d1516h2_8daaf6152771_cb7bf5808d99
 *     | |   |  | |  | |________|________|
 *     | |   |  | |  |     section 2   section 3
 *     | |   |  | |  first+last ALPN
 *     | |   |  | cipher count, then extension count (two decimal digits each)
 *     | |   | SNI present (d) or absent (i)
 *     | |   highest TLS version OFFERED (not the negotiated one)
 *     | transport: t TLS, q QUIC
 *
 * ## Section 3 changes with connection state, so `correlator()` leaves it out
 *
 * Section 2 hashes the cipher list sorted; section 3 hashes the extension list sorted
 * (minus SNI and ALPN) plus the signature algorithms. With the STANDARD FoxIO algorithm
 * the full value is stable per engine across fresh connections — measured 2026-10-04 by
 * `research/fingerprinting/ja4/measure.mjs` (Chromium 10/10, Firefox 5/5, WebKit 4/4;
 * the Chromium/WebKit extension shuffle is absorbed by the sort). An earlier revision of
 * this docblock reported six distinct values from six Chromium connections; that came
 * from a non-standard algorithm that hashed the extensions unsorted (notes/08, notes/14).
 *
 * Section 3 still moves for every engine measured when the connection RESUMES a TLS
 * session (`pre_shared_key` is offered, so the extension set changes), and the whole
 * value changes over QUIC. `correlator()` therefore returns sections 1 and 2, and
 * `sectionThreeIsStable()` stays false: one browser on a resumed connection must not
 * read as a second browser.
 */
final readonly class Ja4
{
    /**
     * The longest a well-formed JA4 can be. Bound so a hostile header cannot make the
     * parser do unbounded work, and small enough that the bound is never the thing that
     * rejects a legitimate value.
     */
    public const MAX_LENGTH = 64;

    /**
     * `t`/`q`, version, SNI, 4 hex of counts, 2 of ALPN.
     */
    private const SECTION_ONE = '/^[tq][0-9a-z]{2}[di][0-9a-f]{4}[a-z0-9]{2}$/';

    private const HASH_SECTION = '/^[0-9a-f]{12}$/';

    private function __construct(
        public string $value,
        public string $sectionOne,
        public string $sectionTwo,
        public string $sectionThree,
    ) {}

    /**
     * Parse and validate, or null when the value is not a JA4.
     *
     * Null rather than a partially-populated object: a fingerprint that failed
     * validation is not a weaker fingerprint, it is not a fingerprint. Returning an
     * object with a null section would push that decision to every caller, and one of
     * them would use it.
     */
    public static function parse(string $raw): ?self
    {
        $value = strtolower(trim($raw));

        if ($value === '' || strlen($value) > self::MAX_LENGTH) {
            return null;
        }

        $parts = explode('_', $value);
        if (count($parts) !== 3) {
            return null;
        }

        [$one, $two, $three] = $parts;

        if (preg_match(self::SECTION_ONE, $one) !== 1) {
            return null;
        }

        if (preg_match(self::HASH_SECTION, $two) !== 1 || preg_match(self::HASH_SECTION, $three) !== 1) {
            return null;
        }

        return new self($value, $one, $two, $three);
    }

    /**
     * The stable half: sections 1 and 2.
     *
     * This is the value to store, compare, or feed to a profile table. Section 3 is
     * deliberately excluded — see the class docblock for the measurement.
     */
    public function correlator(): string
    {
        return $this->sectionOne.'_'.$this->sectionTwo;
    }

    public function isQuic(): bool
    {
        return str_starts_with($this->sectionOne, 'q');
    }

    /**
     * Is a SNI present?
     *
     * Read from position 3 of section 1 only — `d` (domain, SNI present) or `i` (no SNI,
     * e.g. an IP literal). The first version tested `str_contains($sectionOne, 'd')`, which
     * also matched a `d` elsewhere in the section: the DTLS version codes (`d1`, `d2`,
     * `d3`) and any ALPN whose first or last character is `d`, so a no-SNI hello could
     * read as SNI-present. Every fingerprint captured against `https://127.0.0.1/` has `i`
     * for that reason alone, which is why those captures do not match the published
     * Chrome values even though the browsers are the same.
     */
    public function hasSni(): bool
    {
        return ($this->sectionOne[3] ?? '') === 'd';
    }

    /**
     * The highest TLS version the client OFFERED (supported_versions), as JA4 encodes it:
     * `13`, `12`, `11`, `10`, `s2`, `s3`. Not the negotiated version (round-1 WS-12).
     */
    public function tlsVersion(): string
    {
        return substr($this->sectionOne, 1, 2);
    }

    /**
     * Number of cipher suites offered, from section 1.
     *
     * DECIMAL, not hex. The reference implementation formats the count with `%02d`, so a
     * client offering fifteen cipher suites produces the characters `15` — which read as
     * 0x15 = 21 to anyone who assumes hex. This accessor parsed it as hex and returned
     * 21 for a fifteen-cipher ClientHello, which is wrong in a way that would quietly
     * mis-score every profile.
     *
     * Null when the count is `99`, which is JA4's cap and means "99 or more" — a real
     * browser offers 15-25, so 99 means something that is not offering a browser's list.
     */
    public function cipherCount(): ?int
    {
        $raw = substr($this->sectionOne, 4, 2);

        return $raw === '99' ? null : (int) $raw;
    }

    /**
     * Number of extensions offered, from section 1. Same decimal encoding and same `99`
     * cap as `cipherCount()`.
     */
    public function extensionCount(): ?int
    {
        $raw = substr($this->sectionOne, 6, 2);

        return $raw === '99' ? null : (int) $raw;
    }

    /**
     * First and last character of the first ALPN value, or `00` when none was offered.
     *
     * `h2` is HTTP/2, `h1` is HTTP/1.1, and `00` means no ALPN at all — which no
     * current browser does, so it is a cheap thing to notice.
     */
    public function alpn(): string
    {
        return substr($this->sectionOne, 8, 2);
    }

    /**
     * False: section 3 changes when a TLS session is resumed, for every engine measured.
     *
     * Exists so the exclusion of section 3 from `correlator()` is a named, tested property
     * rather than a comment. A deployment whose terminator reports a resumption-independent
     * value (FoxIO's `$http_ssl_ja4one` is one such idea; not verified here) has evidence
     * for its own traffic and can act on it, but only having measured it.
     */
    public function sectionThreeIsStable(): bool
    {
        return false;
    }

    /**
     * Is this a shape a real browser could plausibly produce?
     *
     * Not a verdict, and deliberately weak. Every threshold here is a floor far below
     * what Chromium, Firefox and WebKit actually send (15-16 ciphers, 6-16 extensions),
     * so passing costs an honest browser nothing. It exists to catch the shapes that
     * indicate the header was not produced by a TLS terminator at all.
     */
    public function looksLikeABrowser(): bool
    {
        return $this->cipherCount() !== null
            && $this->cipherCount() >= 4
            && $this->extensionCount() !== null
            && $this->extensionCount() >= 4
            && $this->tlsVersion() !== 's2'
            && $this->tlsVersion() !== 's3';
    }
}

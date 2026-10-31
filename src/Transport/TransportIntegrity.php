<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Transport;

use NutriCompare\Fingerprint\Crawlers\TrafficClassification;
use NutriCompare\Fingerprint\Rules\EnvironmentConsistency;
use NutriCompare\Fingerprint\Support\TransportFinding;
use NutriCompare\Fingerprint\Support\TransportIntegrityResult;
use NutriCompare\Fingerprint\Support\TransportRequestFacts;

/**
 * Inspects what the server can see about a request, and reports the parts that a
 * conforming browser cannot produce.
 *
 * ## The whole idea in one paragraph
 *
 * Client-side fingerprinting is a *claim*. Everything the page reports can be
 * written by an attacker, so a system that scores the claim is scoring the
 * attacker's own homework. This class reads only what arrived over the wire. It
 * produces two things: `findings`, which are things a conforming browser does not
 * do, and `witnesses`, which are merely observed. The observed ones exist to be
 * contradicted later by `EnvironmentConsistency`, which compares them against the
 * client's JavaScript. Neither is used to make a decision on its own.
 *
 * ## What "over the wire" does and does not buy — a correction
 *
 * An earlier version of this docblock said the client "cannot rewrite [the
 * transport] without owning a real browser and a real network stack". That is
 * true of FRAME-level evidence and false of header presence, and the difference
 * decides what this class is worth, so it is worth being exact.
 *
 * A client can set any request header it likes. So a competent HTTP client that
 * adds `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`, `Sec-Fetch-User: ?1`,
 * `Upgrade-Insecure-Requests: 1`, a browser-shaped `Accept` and an
 * `Accept-Language` defeats every header-presence check in this file, and produces
 * zero findings. That is not a bug to be fixed; it is a property of the observation
 * point, and it was measured rather than assumed.
 *
 * What is NOT reachable by header is:
 *
 *   - the HTTP/2 frame itself (a Host header next to `:authority`, `h2_host_with_authority`),
 *     because that is below the header layer — judged only when the headers PHP sees ARE
 *     the client's frame (`headersAreClientFrame`)
 *   - the TLS ClientHello: extension order, ALPN, supported groups, signature
 *     algorithms (JA3 / JA4), because those are below the HTTP layer entirely
 *   - the signed `X-Raw-Header-Order`, because the signature is keyed on a secret
 *     the client never has
 *
 * So the honest summary of this class is: **it raises the cost of a naive client
 * and rewards a competent one.** It does not make a determined spoofer detectable,
 * and an operator should not enable `enforce_codes` expecting it to. What actually
 * makes a determined spoofer detectable is the TLS/HTTP-2 layer, which is Task 3.4 in
 * the design document and is not implemented.
 *
 * The reason the header checks are still worth having is that most hostile traffic is
 * not a competent spoofer. The research measured it: the overwhelming majority of bot
 * traffic never executes vendor JavaScript at all, and a large share of what remains is
 * a hand-rolled client that emits an RFC-violating header by accident. For that
 * population these checks are close to free and almost never wrong.
 *
 * ## Why the hard checks are worth more than everything else
 *
 * Spoofing an HTTP/2 SETTINGS frame, a ClientHello extension order and a
 * cookie acquisition order *simultaneously* is expensive. Emitting a header that
 * RFC 9113 forbids is free by comparison, and almost every hand-rolled HTTP client
 * emits one by accident. These checks therefore have a false-positive rate near
 * zero, cannot change without an RFC change, and cost a few string operations.
 *
 * ## Deployment limits, stated rather than hidden
 *
 * `h2_host_with_authority` runs only when the client spoke HTTP/2 or HTTP/3 AND the headers
 * PHP received are the client's own frame (`$facts->headersAreClientFrame`): the protocol
 * came from the FastCGI param `CLIENT_PROTOCOL` (nginx: `fastcgi_param CLIENT_PROTOCOL
 * $server_protocol` at the hop that terminates the client), not from a separate edge's
 * signed `X-Client-Proto`. Behind an edge the headers PHP sees are the edge→pod HTTP/1.1
 * request, which the proxy rewrites. Two further h2 checks used to live here —
 * `h2_connection_header` and `h2_uppercase_header` — and were deleted (round-2 WS2-1, G-D4i):
 * at a client-facing nginx they are unreachable (nginx answers 400 before PHP runs), and
 * behind an edge every honest HTTP/2 visitor tripped the first one (Cloudflare and nginx
 * `proxy_pass` add their own `Connection` header), which made every ad click a `bot`.
 *
 * `sec_ch_full_version_mismatch` needs `Sec-CH-UA-Full-Version-List`, a high-entropy
 * hint browsers send only after an `Accept-CH` response header asked for it;
 * `CloudflareSecurityMiddleware` sends one on HTML documents while something consumes
 * the hints. The header is an RFC 8941 list (`StructuredFieldList`), and the comparison
 * is the `Chromium` brand's major against the User-Agent's `Chrome/` major ONLY — never
 * Opera's `OPR/`, a WebView's `Version/4.0` or Edge's own brand, which are honest and
 * different (round-2 WS2-2 / STD-19).
 *
 * ## A check that was written and then removed
 *
 * There was a `h1_no_keepalive` check here: "an HTTP/1.1 request with no Connection
 * header". It was correct in the abstract and useless in practice. Every reverse
 * proxy strips hop-by-hop headers, so behind nginx - which is this project's actual
 * deployment - it fired on 100 % of real traffic. A check that always fires carries
 * no information and only trains an operator to ignore the panel.
 *
 * That is the general lesson and it is why the "real browser produces no findings"
 * test in TransportIntegrityTest is the most valuable test in the file: a check that
 * fires on honest traffic is a bug, and only a fixture built from a captured request
 * can catch it. Do not add a check without adding it to that fixture first and
 * watching it stay silent.
 *
 * @see TransportFinding for the hard/soft split and why it exists
 * @see TransportIntegrityResult for findings versus witnesses
 */
final class TransportIntegrity
{
    /**
     * Brand names the UA-CH specification reserves for greasing. They carry no
     * meaningful version and must be excluded from any comparison, which is exactly
     * why a naive "grab the first brand's version" is wrong.
     *
     * ## Why this is a SHAPE and not a list
     *
     * The first version enumerated the six low-entropy variants
     * (`not)a;brand`, `not/a)brand`, `not_a)brand`, `not;a)brand`, `nota)brand`,
     * `not a)brand`). That is the set Chrome uses in the *low-entropy*
     * `Sec-CH-UA` header, and it is what this project's own captures contain.
     *
     * The *high-entropy* list is a different shape. `getHighEntropyValues().brands`
     * and `Sec-CH-UA-Full-Version-List` use the dotted/slashed form
     * (`Not.A/Brand`, lower-casing to `not.a/brand`), which is not in the list above.
     * The high-entropy greased brand is then folded into the hinted major by `max()`.
     *
     * Today that is masked: Chrome's greased version (24) is lower than any real
     * major, so `max()` picks the real one and the check passes. The mask is a
     * coincidence, not a design. GREASE exists precisely to randomise the greased
     * value per origin, and a future browser shipping a greased version ABOVE the real
     * one would make `sec_ch_full_version_mismatch` — a hard finding — fire on honest
     * traffic from every origin that happened to grease high.
     *
     * Matching by shape fixes the class of bug rather than one instance of it: any
     * brand whose lower-cased name starts with `not`, contains `brand`, and has no
     * digit is a GREASE brand, whatever punctuation the engine chose this time.
     *
     * @var list<string>
     */
    private const GREASE_BRANDS = ['not)a;brand', 'not/a)brand', 'not_a)brand', 'not;a)brand', 'nota)brand', 'not a)brand', 'not.a/brand'];

    /**
     * Is this brand name one of the reserved GREASE placeholders?
     *
     * Shape rather than enumeration, for the reason given on GREASE_BRANDS. The digit
     * exclusion is what makes it safe: a real brand name never contains a digit, and
     * the greased value attached to a GREASE brand is precisely the part that must not
     * be compared.
     */
    private function isGreaseBrand(string $brand): bool
    {
        $lower = strtolower($brand);

        if (in_array($lower, self::GREASE_BRANDS, true)) {
            return true;
        }

        return str_starts_with($lower, 'not')
            && str_contains($lower, 'brand')
            && preg_match('/\d/', $lower) !== 1;
    }

    /**
     * @param  list<array{0: string, 1: string}>  $headers  name/value pairs in wire order, ORIGINAL case preserved
     */
    public function analyse(array $headers, TransportRequestFacts $facts): TransportIntegrityResult
    {
        $findings = [];
        $witnesses = [];

        $lookup = [];
        foreach ($headers as [$name, $value]) {
            $lower = strtolower($name);
            // First occurrence wins. A second Cookie or Host header is itself
            // suspicious but is not something this class reports, and letting a
            // later duplicate silently override an earlier one would make the
            // whole analysis depend on list position in a way nobody could audit.
            $lookup[$lower] ??= $value;
        }

        $get = static fn (string $name): ?string => $lookup[$name] ?? null;
        $protocol = $get('sec-fetch-mode');
        $dest = $get('sec-fetch-dest');
        $user = $get('sec-fetch-user');

        // ---------------------------------------------------------------- hard
        if ($facts->clientSpokeHttp2 && $facts->headersAreClientFrame && $get('host') !== null && $facts->authority !== null) {
            $findings[] = TransportFinding::hard(
                'h2_host_with_authority',
                'HTTP/2 request carries both a Host header and :authority. RFC 9113 section 8.3.1 permits both only when '
                    .'they are equal and browsers send the pseudo-header alone.',
            );
        }

        if ($protocol === 'cors' && $dest === 'document') {
            $findings[] = TransportFinding::hard(
                'fetch_mode_cors_document',
                'Sec-Fetch-Mode is cors while Sec-Fetch-Dest is document. The fetch standard does not allow this pair.',
            );
        }

        // SOFT, not hard, and that is a correction.
        //
        // The finding was originally `hard` on the reasoning that "every
        // browser-initiated navigation sends Sec-Fetch-User: ?1". That is the part that
        // is wrong: the header is only sent when the navigation had *user activation*,
        // and a great many navigations do not. Meta-refresh, a scripted redirect after
        // a session expiry, a locale or A/B router, session restore, and a `history`
        // entry the user did not click all produce a navigation with
        // `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document` and no
        // `Sec-Fetch-User`.
        //
        // As a hard finding this carried the `transport_default` weight of 45, which is
        // score 68 — band `challenge` — and made it eligible for `enforce_codes`, where
        // it would 403 a real visitor following a legitimate redirect. It is a protocol
        // *convention*, not an RFC requirement, so it is soft now: it informs a score
        // and shows up on the operator's screen, and it cannot by itself refuse anyone.
        if ($protocol === 'navigate' && $dest === 'document' && $user === null) {
            $findings[] = TransportFinding::soft(
                'fetch_user_missing',
                'Sec-Fetch-Mode is navigate with Sec-Fetch-Dest document but no Sec-Fetch-User. '
                    .'A navigation with user activation always sends Sec-Fetch-User: ?1, so its absence '
                    .'suggests a redirect or restore rather than a click.',
            );
        }

        if ($get('sec-ch-ua') !== null && $get('sec-ch-ua-mobile') === null) {
            // The default low-entropy set travels together from a browser, but a proxy or WAF
            // that strips one hint and forwards the other produces the same request for every
            // Chromium visitor behind it. Hard only when the headers are the client's own frame
            // (the D4 lesson: a header check behind an edge judges the edge).
            $detail = 'Sec-CH-UA is present without Sec-CH-UA-Mobile. The RFC 8941 default low-entropy set always travels together, '
                .'so one without the other means the headers were assembled by hand or a proxy dropped one.';
            $findings[] = $facts->headersAreClientFrame
                ? TransportFinding::hard('sec_ch_partial_default_set', $detail)
                : TransportFinding::soft('sec_ch_partial_default_set', $detail);
        }

        $versionMismatch = $this->checkFullVersionList($get('sec-ch-ua-full-version-list'), $get('user-agent'));
        if ($versionMismatch !== null) {
            $findings[] = $versionMismatch;
        }

        // A User-Agent that claims a search crawler whose identity the vendor's DNS or published
        // list contradicts. Hard: it is a statement the request cannot make honestly. It scores 45
        // (challenge, never block) like every other single check.
        $impersonation = $facts->crawler === null
            ? null
            : TrafficClassification::impersonationFindingFor($facts->crawler);
        if ($impersonation !== null) {
            $findings[] = $impersonation;
        }

        // ---------------------------------------------------------------- soft
        $accept = $get('accept');

        // `document_accept_star` was previously written as
        // `$facts->isDocumentRequest && $accept === '*/*'`, which is UNSATISFIABLE:
        // `isDocumentRequest` requires the Accept header to contain `text/html`, and a
        // bare wildcard does not. The check could never fire for anyone, while
        // config/security.php presented it as the worked example of what a soft finding
        // looks like. Dead code that reads as coverage is worse than no code.
        //
        // The obvious repair — "does a document request contain a wildcard media range?"
        // — is WORSE than the bug, and shipped for about ten minutes before that was
        // measured. A real Chromium navigation sends
        // `text/html,…,image/webp,*/*;q=0.8`: the wildcard is always there, as the
        // lowest-priority catch-all. That version fired on 100% of real browser
        // navigations and the honest-traffic fixture caught it immediately.
        //
        // The predicate that is both satisfiable and specific keys on
        // `Sec-Fetch-Dest`, which is set by the browser from the real destination and
        // is independent of Accept. So: a navigation, judged by the transport, whose
        // Accept is *nothing but* the wildcard.
        if ($dest === 'document' && $accept === '*/*') {
            $findings[] = TransportFinding::soft(
                'document_accept_star',
                'A document request sent a wildcard-only Accept header. Every browser sends a rich Accept header for navigations.',
            );
        }

        if ($facts->isDocumentRequest && $get('upgrade-insecure-requests') === null) {
            $findings[] = TransportFinding::soft(
                'document_no_upgrade_insecure',
                'A document request omitted Upgrade-Insecure-Requests, which every current browser sends on navigations.',
            );
        }

        if ($get('accept-language') === null) {
            $findings[] = TransportFinding::soft(
                'no_accept_language',
                'No Accept-Language header. Browsers always send one.',
            );
        }

        if ($protocol === 'none' && $get('referer') !== null) {
            $findings[] = TransportFinding::soft(
                'fetch_none_with_referer',
                'Sec-Fetch-Mode is none yet a Referer is present. The fetch standard sends no referrer with mode none.',
            );
        }

        if ($facts->isDocumentRequest && $protocol === null && $dest === null) {
            $findings[] = TransportFinding::soft(
                'sec_fetch_missing',
                'A document request carried no Sec-Fetch-* header at all. Every current browser sends the family.',
            );
        }

        // ----------------------------------------------------------- witnesses
        $witnesses = [
            'protocol_is_http2' => $facts->clientSpokeHttp2,
            'header_order_available' => $facts->headerOrderAvailable,
            'method' => $facts->method,
            'is_document' => $facts->isDocumentRequest,
            'user_agent' => $get('user-agent'),
            'accept_language' => $get('accept-language'),
            'accept' => $accept,
            'accept_encoding' => $get('accept-encoding'),
            'referer' => $get('referer'),
            'host' => $get('host'),
            'authority' => $facts->authority,
            'cookie_names' => $this->cookieNames($get('cookie')),
            'sec_ch_ua' => $get('sec-ch-ua'),
            'sec_ch_ua_mobile' => $get('sec-ch-ua-mobile'),
            'sec_ch_ua_platform' => $get('sec-ch-ua-platform'),
            'sec_ch_ua_platform_version' => $get('sec-ch-ua-platform-version'),
            'sec_ch_ua_arch' => $get('sec-ch-ua-arch'),
            'sec_ch_ua_model' => $get('sec-ch-ua-model'),
            'sec_ch_ua_bitness' => $get('sec-ch-ua-bitness'),
            'sec_ch_ua_full_version_list' => $get('sec-ch-ua-full-version-list'),
            // The device hints a host asks for with `Accept-CH` (README, "Per-application
            // configuration"). A JavaScript spoof of `deviceMemory`, the pixel ratio or
            // `userAgentData` does not change what the browser put on the wire; each is read by
            // one rule in EnvironmentConsistency, both-present only.
            'sec_ch_device_memory' => $get('sec-ch-device-memory'),
            'sec_ch_dpr' => $get('sec-ch-dpr'),
            'sec_ch_viewport_width' => $get('sec-ch-viewport-width'),
            'sec_fetch_mode' => $protocol,
            'sec_fetch_dest' => $dest,
            'sec_fetch_user' => $user,
            'protocol' => $facts->clientProtocol,
            // The FULL standard JA4: section b alone does not separate engines, and section c
            // is stable per engine over fresh connections (notes/14, measured 2026-10-04).
            'ja4' => $facts->ja4?->value,
            'ja4_section_one' => $facts->ja4?->sectionOne,
            'sec_fetch_site' => $get('sec-fetch-site'),
            'upgrade_insecure_requests' => $get('upgrade-insecure-requests'),
        ];

        if ($facts->headerOrderAvailable) {
            // The order itself, not the set. This is the input to JA4H section `b`
            // and to the per-engine order profile table.
            $witnesses['header_order'] = implode('|', array_map(
                static fn (array $pair): string => strtolower($pair[0]),
                $headers,
            ));
        }

        return new TransportIntegrityResult($findings, array_filter(
            $witnesses,
            // A witness that is null carries no information and would make every
            // consumer write a null check twice. Dropping them here means
            // `witness()` returning null unambiguously means "not present".
            static fn (mixed $v): bool => $v !== null,
        ));
    }

    /**
     * `Sec-CH-UA-Full-Version-List` against the User-Agent's engine major.
     *
     * The header is an RFC 8941 structured-field list, as captured from Chromium:
     *
     *     "Chromium";v="153.0.1234.5", "Not_A Brand";v="8.0.0.0"
     *
     * Compared like with like: the `Chromium` brand's major against the UA's `Chrome/`
     * token, both of which every Chromium-based browser sends. Opera's `OPR/117` next to
     * `Chromium 132`, a WebView's `Version/4.0`, Edge's and Samsung's own brands are honest
     * and different, so they are never consulted (round-2 WS2-2). Null (no finding) whenever
     * the evidence is incomplete or unparseable — an invalid list is no evidence.
     */
    private function checkFullVersionList(?string $header, ?string $userAgent): ?TransportFinding
    {
        if ($header === null || $header === '' || $userAgent === null) {
            return null;
        }

        $hintedMajor = null;
        foreach (self::parseBrandList($header) as [$brand, $version]) {
            if ($this->isGreaseBrand($brand) || strtolower(trim($brand)) !== 'chromium') {
                continue;
            }
            if (preg_match('/^\d+/', $version, $m) !== 1) {
                continue;
            }
            $hintedMajor = (int) $m[0];
            break;
        }

        if ($hintedMajor === null) {
            return null;
        }

        $engine = EnvironmentConsistency::engineVersionFromUserAgent($userAgent);
        if ($engine === null || $engine[0] !== 'chrome' || $engine[1] === $hintedMajor) {
            return null;
        }

        return TransportFinding::hard(
            'sec_ch_full_version_mismatch',
            'The User-Agent major version disagrees with Sec-CH-UA-Full-Version-List. '
                .'A copied User-Agent string cannot pass this check.',
        );
    }

    /**
     * The `"brand";v="version"` members of an RFC 8941 list, in order, through the one
     * structured-field parser. An invalid field (an inner list, a bad escape) yields `[]`.
     *
     * @return list<array{0: string, 1: string}>
     */
    public static function parseBrandList(string $header): array
    {
        return StructuredFieldList::brandList($header);
    }

    /**
     * Cookie names, in the order they arrived.
     *
     * Only the names. Values are the user's session material and this system has
     * no use for them; reading them into a log line would be gratuitous. The
     * order is the signal, not the content, which is why the list is preserved.
     *
     * @return list<string>
     */
    private function cookieNames(?string $cookieHeader): array
    {
        if ($cookieHeader === null || $cookieHeader === '') {
            return [];
        }

        $names = [];
        foreach (explode(';', $cookieHeader) as $pair) {
            $name = trim(explode('=', $pair, 2)[0]);
            if ($name !== '') {
                $names[] = $name;
            }
        }

        return $names;
    }
}

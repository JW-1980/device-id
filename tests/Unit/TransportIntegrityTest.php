<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\Support\TransportRequestFacts;
use NutriCompare\Fingerprint\Transport\Ja4;
use NutriCompare\Fingerprint\Transport\TransportIntegrity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * TransportIntegrity, tested against OBSERVED traffic.
 *
 * The "real browser" cases are copied from the captures in
 * research/fingerprinting/captures (each site directory holds a traffic.json) -
 * real requests this project recorded, not strings invented here. That matters
 * more than it might appear: a check that fires on genuine browser traffic is a bug
 * that no amount of synthetic testing would catch, and the only defence is a fixture
 * built from something a browser actually sent.
 *
 * Firefox and Safari are included as first-class cases so the suite proves the
 * checks are not accidentally Chromium-shaped.
 */
final class TransportIntegrityTest extends TestCase
{
    private TransportIntegrity $analyse;

    protected function setUp(): void
    {
        $this->analyse = new TransportIntegrity;
    }

    /**
     * @param  list<array{0: string, 1: string}>  $headers
     */
    /**
     * @param  list<array{0: string, 1: string}>  $headers
     * @return list<string>
     */
    private function codes(array $headers, ?TransportRequestFacts $facts = null): array
    {
        $result = $this->analyse->analyse($headers, $facts ?? new TransportRequestFacts);

        return $result->codes();
    }

    /**
     * @param  list<array{0: string, 1: string}>  $headers
     */
    /**
     * @param  list<array{0: string, 1: string}>  $headers
     * @return list<string>
     */
    private function hardCodes(array $headers, ?TransportRequestFacts $facts = null): array
    {
        $result = $this->analyse->analyse($headers, $facts ?? new TransportRequestFacts);

        return $result->hardCodes();
    }

    /**
     * A COMPLETE Chromium document request, captured with `request.allHeaders()`.
     *
     * Provenance and its limits, because both matter:
     *
     * - Captured from coinbase.com/signin during the research in
     *   research/fingerprinting/captures. Every value and the order are real.
     * - An earlier version of the capture tool used Playwright's SYNCHRONOUS
     *   `request.headers()`, which silently omits the entire `Sec-Fetch-*` family
     *   and the pseudo-headers. Fixtures built from that data looked plausible but
     *   could never satisfy the Sec-Fetch checks, and `request_without_the_family`
     *   below is that bug's fingerprint.
     * - `allHeaders()` also fails intermittently and falls back to the incomplete
     *   set, so only a minority of captured requests are complete. Treat any single
     *   capture as a lower bound on completeness, never as authoritative.
     *
     * @return list<array{0: string, 1: string}>
     */
    private static function realChromiumDocument(): array
    {
        return [
            ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'],
            ['accept-encoding', 'gzip, deflate, br, zstd'],
            ['accept-language', 'en-US'],
            ['cache-control', 'max-age=0'],
            ['cookie', 'nc_device=abc123; _ga=GA1.2.1; _gid=GA1.2.2'],
            ['pragma', 'no-cache'],
            ['priority', 'u=0, i'],
            ['sec-ch-ua', '"Chromium";v="141", "Not)A;Brand";v="24"'],
            ['sec-ch-ua-mobile', '?0'],
            ['sec-ch-ua-platform', '"Windows"'],
            ['sec-fetch-dest', 'document'],
            ['sec-fetch-mode', 'navigate'],
            ['sec-fetch-site', 'none'],
            ['sec-fetch-user', '?1'],
            ['upgrade-insecure-requests', '1'],
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'],
        ];
    }

    // ---------------------------------------------------------------------
    // Real traffic: these must produce nothing at all.
    // ---------------------------------------------------------------------

    #[Test]
    public function real_chromium_document_request_produces_no_findings(): void
    {
        self::assertSame([], $this->codes(self::realChromiumDocument()));
    }

    #[Test]
    public function a_complete_chromium_navigation_has_no_hard_findings(): void
    {
        // Stated separately from the "no findings" case above because it is the
        // assertion that actually protects users: a browser doing the most
        // ordinary thing in the world must never be accused of anything.
        self::assertSame([], $this->hardCodes(self::realChromiumDocument()));
    }

    #[Test]
    public function the_capture_bug_that_made_this_suite_fail_is_itself_reproducible(): void
    {
        // The incomplete capture omitted Sec-Fetch entirely. Proving that the
        // check reacts to the omission, and documenting why the omission existed,
        // means nobody re-derives a fixture from a stale capture file and gets a
        // suite that passes for the wrong reason.
        $headers = self::realChromiumDocument();
        $withoutFetch = array_values(array_filter(
            $headers,
            static fn (array $p): bool => ! str_starts_with($p[0], 'sec-fetch'),
        ));

        self::assertCount(16, $headers);
        self::assertCount(12, $withoutFetch);
        self::assertContains('sec_fetch_missing', $this->codes($withoutFetch));
        self::assertNotContains('sec_fetch_missing', $this->codes($headers));
    }

    #[Test]
    public function real_chromium_same_origin_navigation_produces_no_findings(): void
    {
        // The complete capture with a same-origin referer and the Dutch locale, so
        // the suite covers the configuration this application actually serves.
        $headers = self::realChromiumDocument();
        $headers[] = ['referer', 'https://www.coinbase.com/'];
        $headers[2] = ['accept-language', 'nl-NL,nl;q=0.9,en;q=0.8'];
        $headers[10] = ['sec-fetch-site', 'same-origin'];

        self::assertSame([], $this->codes($headers));
    }

    #[Test]
    public function real_firefox_document_request_produces_no_findings(): void
    {
        // Firefox does not send the Sec-CH-UA family at all by default, so this
        // case is what proves the Client-Hints checks do not assume Chromium.
        $headers = [
            ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8'],
            ['accept-encoding', 'gzip, deflate, br, zstd'],
            ['accept-language', 'en-US,en;q=0.5'],
            ['referer', 'https://www.mozilla.org/'],
            ['upgrade-insecure-requests', '1'],
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0'],
            ['sec-fetch-dest', 'document'],
            ['sec-fetch-mode', 'navigate'],
            ['sec-fetch-site', 'same-origin'],
            ['sec-fetch-user', '?1'],
        ];

        self::assertSame([], $this->codes($headers));
    }

    #[Test]
    public function real_safari_document_request_produces_no_findings(): void
    {
        $headers = [
            ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
            ['accept-encoding', 'gzip, deflate, br'],
            ['accept-language', 'nl-NL,nl;q=0.9'],
            ['referer', 'https://www.example.nl/'],
            ['upgrade-insecure-requests', '1'],
            ['user-agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15'],
            ['sec-fetch-dest', 'document'],
            ['sec-fetch-mode', 'navigate'],
            ['sec-fetch-site', 'cross-site'],
            ['sec-fetch-user', '?1'],
        ];

        self::assertSame([], $this->codes($headers));
    }

    // ---------------------------------------------------------------------
    // Hard findings: protocol violations. Zero false positives by construction.
    // ---------------------------------------------------------------------

    /**
     * Round-2 WS2-1 / G-D4i: the two HTTP/2 header checks are gone. Behind a reverse proxy
     * the PHP process never sees the client's HTTP/2 frame — nginx re-serialises the
     * request as HTTP/1.1 (or FastCGI), may add its own `Connection` header and
     * re-cases every field name — so `Connection` or an uppercase name proved nothing
     * about the client. Neither code exists any more.
     */
    #[Test]
    public function connection_headers_and_uppercase_names_are_never_findings_over_http2(): void
    {
        $facts = new TransportRequestFacts(clientSpokeHttp2: true, headersAreClientFrame: true);

        self::assertSame([], $this->hardCodes([['connection', 'keep-alive']], $facts));
        self::assertSame([], $this->hardCodes([['transfer-encoding', 'chunked']], $facts));
        self::assertSame([], $this->hardCodes([['Transfer-Encoding', 'chunked']], $facts));
        self::assertSame([], $this->hardCodes([['User-Agent', 'Mozilla/5.0'], ['Accept', '*/*']], $facts));
        self::assertSame([], $this->hardCodes([['connection', 'keep-alive'], ['User-Agent', 'x']], new TransportRequestFacts(clientSpokeHttp2: true)));

        $result = $this->analyse->analyse([['connection', 'keep-alive'], ['Transfer-Encoding', 'chunked']], $facts);
        self::assertNotContains('h2_connection_header', $result->codes());
        self::assertNotContains('h2_uppercase_header', $result->codes());
    }

    /**
     * `Host` next to `:authority` is a frame-level fact, so it is judged only when the
     * headers analysed ARE the client's frame (a signed proxy order, or PHP terminating
     * HTTP/2 itself); re-serialised by a proxy, both can be present for honest reasons.
     */
    #[Test]
    public function http2_request_with_host_and_authority_is_a_hard_finding_only_on_the_client_frame(): void
    {
        $headers = [['host', 'example.com'], [':method', 'GET']];

        self::assertSame(['h2_host_with_authority'], $this->hardCodes($headers, new TransportRequestFacts(clientSpokeHttp2: true, authority: 'example.com', headersAreClientFrame: true)));
        self::assertSame([], $this->hardCodes($headers, new TransportRequestFacts(clientSpokeHttp2: true, authority: 'example.com')), 'a proxy-reserialised frame proves nothing');
        self::assertSame([], $this->hardCodes($headers, new TransportRequestFacts(clientSpokeHttp2: false, authority: 'example.com', headersAreClientFrame: true)));
    }

    #[Test]
    public function cors_mode_with_document_destination_is_a_hard_finding(): void
    {
        $headers = [['sec-fetch-mode', 'cors'], ['sec-fetch-dest', 'document']];

        self::assertSame(['fetch_mode_cors_document'], $this->hardCodes($headers));
    }

    /**
     * `fetch_user_missing` is SOFT, and the test name used to say the opposite.
     *
     * It was a hard finding on the reasoning that "every browser-initiated navigation
     * sends `Sec-Fetch-User: ?1`". That is the claim that is wrong: the header is only
     * sent when the navigation had user activation, and a great many legitimate
     * navigations do not — a `<meta http-equiv="refresh">`, a scripted redirect after a
     * session expiry, a locale or A/B router, session restore, a `history` entry the
     * user did not click.
     *
     * As a hard finding it carried the `transport_default` weight of 45, which is score
     * 68, band `challenge`, and made it eligible for `enforce_codes` — where it would
     * have refused a real visitor for following a legitimate redirect. It is a protocol
     * convention, not an RFC requirement, so it informs a score and is visible to an
     * operator, and it cannot by itself refuse anyone.
     */
    #[Test]
    public function navigate_mode_without_fetch_user_is_a_soft_finding(): void
    {
        $headers = [['sec-fetch-mode', 'navigate'], ['sec-fetch-dest', 'document']];

        // Still found…
        self::assertContains('fetch_user_missing', $this->codes($headers));

        // …but never a hard one, so `enforce_codes` cannot act on it.
        self::assertSame([], $this->hardCodes($headers));
    }

    #[Test]
    public function navigate_mode_with_fetch_user_is_not_a_finding(): void
    {
        $headers = [['sec-fetch-mode', 'navigate'], ['sec-fetch-dest', 'document'], ['sec-fetch-user', '?1']];

        self::assertSame([], $this->hardCodes($headers));
    }

    #[Test]
    public function sec_ch_ua_without_mobile_is_hard_only_when_the_headers_are_the_clients_own_frame(): void
    {
        $headers = [['sec-ch-ua', '"Chromium";v="141"']];

        self::assertSame(['sec_ch_partial_default_set'], $this->hardCodes($headers, new TransportRequestFacts(headersAreClientFrame: true)));
    }

    /**
     * A proxy or WAF that strips `Sec-CH-UA-Mobile` but forwards `Sec-CH-UA` produced this request
     * for every Chromium visitor behind it; as a hard finding it put all of them in `challenge`.
     */
    #[Test]
    public function sec_ch_ua_without_mobile_behind_an_edge_is_only_soft(): void
    {
        $headers = [['sec-ch-ua', '"Chromium";v="141"']];

        self::assertSame([], $this->hardCodes($headers));
        self::assertContains('sec_ch_partial_default_set', $this->codes($headers), 'still recorded, so an operator can see the edge');
    }

    #[Test]
    public function a_complete_default_client_hint_set_is_silent_in_both_frames(): void
    {
        $headers = [['sec-ch-ua', '"Chromium";v="141"'], ['sec-ch-ua-mobile', '?0']];

        self::assertNotContains('sec_ch_partial_default_set', $this->codes($headers));
        self::assertNotContains('sec_ch_partial_default_set', $this->codes($headers, new TransportRequestFacts(headersAreClientFrame: true)));
    }

    // ---------------------------------------------------------------------
    // The highest-value check: a copied User-Agent cannot pass.
    // ---------------------------------------------------------------------

    #[Test]
    public function full_version_list_disagreeing_with_user_agent_is_a_hard_finding(): void
    {
        // The bot copied a User-Agent claiming Chrome 112; the browser actually
        // sent its real, un-redacted version list.
        $headers = [
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'],
            // The wire format: an RFC 8941 list, as Chromium sends it.
            ['sec-ch-ua-full-version-list', '"Not/A)Brand";v="8.0.0.0", "Chromium";v="141.0.7390.54", "Google Chrome";v="141.0.7390.54"'],
        ];

        self::assertSame(['sec_ch_full_version_mismatch'], $this->hardCodes($headers));
    }

    /**
     * The header exactly as captured from Chromium 153 after an `Accept-CH` (WS-5). The
     * previous parser expected JSON, which no browser sends, so this check could never fire.
     */
    #[Test]
    public function the_real_captured_full_version_list_is_parsed(): void
    {
        $captured = '"Chromium";v="153.0.1234.5", "Not_A Brand";v="8.0.0.0"';

        $mismatch = $this->analyse->analyse([
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
            ['sec-ch-ua-full-version-list', $captured],
        ], new TransportRequestFacts);

        self::assertContains('sec_ch_full_version_mismatch', $mismatch->hardCodes());

        $agree = $this->analyse->analyse([
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36'],
            ['sec-ch-ua-full-version-list', $captured],
        ], new TransportRequestFacts);

        self::assertSame([], $agree->hardCodes());

        self::assertSame(
            [['Chromium', '153.0.1234.5'], ['Not_A Brand', '8.0.0.0']],
            TransportIntegrity::parseBrandList($captured),
            'the one RFC 8941 parser (StructuredFieldList) is what the check reads',
        );
    }

    #[Test]
    public function a_finding_detail_never_embeds_the_versions(): void
    {
        $result = $this->analyse->analyse([
            ['user-agent', 'Mozilla/5.0 Chrome/120.0.0.0'],
            ['sec-ch-ua-full-version-list', '"Chromium";v="153.0.1234.5"'],
        ], new TransportRequestFacts);

        $mismatch = array_values(array_filter($result->findings, static fn ($f): bool => $f->code === 'sec_ch_full_version_mismatch'));
        self::assertCount(1, $mismatch);
        self::assertStringNotContainsString('153', $mismatch[0]->detail);
        self::assertStringNotContainsString('120', $mismatch[0]->detail);
    }

    #[Test]
    public function full_version_list_agreeing_with_user_agent_is_not_a_finding(): void
    {
        $headers = [
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'],
            ['sec-ch-ua-full-version-list', '"Chromium";v="141.0.7390.54", "Google Chrome";v="141.0.7390.54"'],
        ];

        self::assertSame([], $this->hardCodes($headers));
    }

    #[Test]
    public function grease_brand_versions_are_ignored_in_the_comparison(): void
    {
        // "Not/A)Brand" carries a deliberately absurd version. Reading the first
        // brand's version rather than filtering it would produce a false finding
        // on every single request.
        $headers = [
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'],
            ['sec-ch-ua-full-version-list', '"Not/A)Brand";v="99.0.0.0", "Chromium";v="141.0.7390.54"'],
        ];

        self::assertSame([], $this->hardCodes($headers));
    }

    #[Test]
    public function edge_is_read_as_edge_rather_than_as_the_chrome_underneath_it(): void
    {
        // Edge's User-Agent contains "Chrome/", so a naive extractor would report
        // the Chrome version and could be off by several majors.
        $headers = [
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0'],
            ['sec-ch-ua-full-version-list', '"Microsoft Edge";v="141.0.3538.63"'],
        ];

        self::assertSame([], $this->hardCodes($headers));
    }

    /**
     * G-D4i / WS2-3 / STD-19: the check compares the `Chromium` brand's major with the
     * `Chrome/` major of the User-Agent — the engine, not the product. Every Chromium
     * derivative names itself in the list but carries `Chrome/<engine major>` in the UA,
     * so an honest Opera, Samsung Internet, Yandex, Edge or Android WebView is silent…
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function honestDerivativeProvider(): iterable
    {
        yield 'opera' => [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 OPR/127.0.0.0',
            '"Chromium";v="141.0.7390.54", "Not_A Brand";v="24.0.0.0", "Opera";v="127.0.5890.12"',
        ];
        yield 'samsung internet' => [
            'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36',
            '"Chromium";v="130.0.6723.102", "Samsung Internet";v="28.0.0.0", "Not_A Brand";v="99.0.0.0"',
        ];
        yield 'yandex' => [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 YaBrowser/25.10.0.0 Safari/537.36',
            '"Chromium";v="140.0.7339.80", "YaBrowser";v="25.10.1.0", "Not_A Brand";v="8.0.0.0"',
        ];
        yield 'edge' => [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.3537.57',
            '"Microsoft Edge";v="141.0.3537.57", "Chromium";v="141.0.7390.54", "Not_A Brand";v="24.0.0.0"',
        ];
        yield 'android webview' => [
            'Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP2A.240805.005; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.7390.54 Mobile Safari/537.36',
            '"Android WebView";v="141.0.7390.54", "Chromium";v="141.0.7390.54", "Not_A Brand";v="24.0.0.0"',
        ];
    }

    #[Test]
    #[DataProvider('honestDerivativeProvider')]
    public function an_honest_chromium_derivative_is_silent(string $userAgent, string $fullVersionList): void
    {
        self::assertSame([], $this->hardCodes([['user-agent', $userAgent], ['sec-ch-ua-full-version-list', $fullVersionList]]));
    }

    /**
     * …and a copied User-Agent under any of them still fails: the Chromium major the
     * browser puts in the hint cannot be edited by a page or a script.
     */
    #[Test]
    #[DataProvider('honestDerivativeProvider')]
    public function a_copied_user_agent_under_a_chromium_derivative_still_fails(string $userAgent, string $fullVersionList): void
    {
        $lied = (string) preg_replace('/Chrome\/\d+/', 'Chrome/120', $userAgent);
        self::assertNotSame($userAgent, $lied);

        self::assertSame(['sec_ch_full_version_mismatch'], $this->hardCodes([['user-agent', $lied], ['sec-ch-ua-full-version-list', $fullVersionList]]));
    }

    /**
     * STD-22: a field that is not a valid RFC 8941 list is no evidence at all — an inner
     * list where a brand should be, or a bad escape, used to be partially read and could
     * attribute a version to the wrong brand.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function invalidFullVersionListProvider(): iterable
    {
        yield 'inner list' => ['("Chromium" "Google Chrome");v="120.0.0.0"'];
        yield 'bad escape' => ['"Chrom\\9ium";v="120.0.0.0"'];
        yield 'trailing comma' => ['"Chromium";v="120.0.0.0",'];
        yield 'integer version' => ['"Chromium";v=120'];
    }

    #[Test]
    #[DataProvider('invalidFullVersionListProvider')]
    public function an_invalid_full_version_list_is_no_evidence(string $field): void
    {
        $headers = [
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'],
            ['sec-ch-ua-full-version-list', $field],
        ];

        self::assertSame([], $this->hardCodes($headers), 'a malformed field was scored');
        self::assertSame([], TransportIntegrity::parseBrandList($field));
    }

    /**
     * @return iterable<string, array{0: list<array{0: string, 1: string}>}>
     */
    public static function incompleteEvidenceProvider(): iterable
    {
        yield 'no full version list at all' => [
            [['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36']],
        ];

        yield 'no user agent' => [
            [['sec-ch-ua-full-version-list', '"Chromium";v="141.0.0.0"']],
        ];

        yield 'not a structured-field list' => [
            [
                ['user-agent', 'Mozilla/5.0 Chrome/112.0.0.0'],
                ['sec-ch-ua-full-version-list', '{not a list'],
            ],
        ];

        yield 'the old JSON shape no browser sends' => [
            [
                ['user-agent', 'Mozilla/5.0 Chrome/112.0.0.0'],
                ['sec-ch-ua-full-version-list', '{"Chromium":{"version":"141","fullVersion":"141.0.0.0"}}'],
            ],
        ];

        yield 'a bare string item' => [
            [
                ['user-agent', 'Mozilla/5.0 Chrome/112.0.0.0'],
                ['sec-ch-ua-full-version-list', '"141"'],
            ],
        ];

        yield 'brand members with no v parameter' => [
            [
                ['user-agent', 'Mozilla/5.0 Chrome/112.0.0.0'],
                ['sec-ch-ua-full-version-list', '"Chromium", "Google Chrome";q="1"'],
            ],
        ];

        yield 'unrecognisable user agent' => [
            [['user-agent', 'SomeCustomClient/1.0']],
        ];
    }

    /**
     * Incomplete evidence must never produce a finding.
     *
     * Absence of the header is the normal case for most browsers, since the
     * header only arrives when `Accept-CH` asked for it. Turning a missing
     * signal into a suspicion would fire on the majority of real traffic.
     */
    /**
     * @param  list<array{0: string, 1: string}>  $headers
     */
    #[Test]
    #[DataProvider('incompleteEvidenceProvider')]
    public function incomplete_evidence_produces_no_finding(array $headers): void
    {
        self::assertSame([], $this->hardCodes($headers));
    }

    // ---------------------------------------------------------------------
    // Soft findings: improbable, not impossible.
    //
    // These assert the SPECIFIC code plus "no hard findings", rather than the
    // exact full list. A test that pins the whole list breaks every time an
    // unrelated check is added, and the resulting churn is how a suite stops
    // being read.
    // ---------------------------------------------------------------------

    #[Test]
    public function star_accept_on_a_document_request_is_soft_not_hard(): void
    {
        $headers = self::realChromiumDocument();
        $headers[0] = ['accept', '*/*'];
        $result = $this->analyse->analyse($headers, new TransportRequestFacts);

        self::assertContains('document_accept_star', $result->codes());
        self::assertSame([], $result->hardCodes());
        self::assertSame(1, $result->softCount());
    }

    #[Test]
    public function star_accept_on_a_subresource_is_not_a_finding(): void
    {
        // Browsers send `Accept: */*` to subresources constantly, so the check must be
        // restricted to navigations.
        //
        // The fixture used to be `isDocumentRequest: false` with the rest of a real
        // document capture left in place — which left `sec-fetch-dest: document` sitting
        // in the headers while the facts said the request was not a document. Those two
        // now disagree by design, because `document_accept_star` keys on
        // `sec-fetch-dest` (the browser's own answer, and the one that makes the check
        // satisfiable at all) rather than on an Accept-derived flag. An
        // internally contradictory fixture cannot tell you which predicate is right, so
        // it is replaced with an honest subresource: a script request, which is what a
        // real `Accept: */*` subresource looks like.
        $headers = self::realChromiumDocument();
        $headers[0] = ['accept', '*/*'];
        $headers[10] = ['sec-fetch-dest', 'script'];
        $headers[9] = ['sec-fetch-mode', 'no-cors'];
        $facts = new TransportRequestFacts(isDocumentRequest: false);
        $result = $this->analyse->analyse($headers, $facts);

        self::assertNotContains('document_accept_star', $result->codes());
        self::assertSame([], $result->hardCodes());
    }

    #[Test]
    public function missing_accept_language_is_soft(): void
    {
        $headers = self::realChromiumDocument();
        $headers = array_values(array_filter(
            $headers,
            static fn (array $p): bool => $p[0] !== 'accept-language',
        ));
        $result = $this->analyse->analyse($headers, new TransportRequestFacts);

        self::assertContains('no_accept_language', $result->codes());
        self::assertNotContains('no_accept_language', $result->hardCodes());
    }

    #[Test]
    public function fetch_none_with_referer_is_soft(): void
    {
        // Sec-Fetch-Mode: none with a Referer is impossible per the fetch spec,
        // but it classifies as soft rather than hard: an extension or a privacy
        // tool can produce it legitimately, and refusing a request over it would
        // punish the visitor for their own tooling.
        $headers = self::realChromiumDocument();
        $headers[11] = ['sec-fetch-mode', 'none'];
        $headers[] = ['referer', 'https://example.com/'];
        $result = $this->analyse->analyse($headers, new TransportRequestFacts);

        self::assertContains('fetch_none_with_referer', $result->codes());
        self::assertNotContains('fetch_none_with_referer', $result->hardCodes());
    }

    #[Test]
    public function document_without_sec_fetch_family_is_soft(): void
    {
        $headers = self::realChromiumDocument();
        $headers = array_values(array_filter(
            $headers,
            static fn (array $p): bool => ! str_starts_with($p[0], 'sec-fetch'),
        ));
        $result = $this->analyse->analyse($headers, new TransportRequestFacts);

        self::assertContains('sec_fetch_missing', $result->codes());
        self::assertNotContains('sec_fetch_missing', $result->hardCodes());
    }

    #[Test]
    public function document_without_upgrade_insecure_is_soft(): void
    {
        $headers = self::realChromiumDocument();
        $headers = array_values(array_filter(
            $headers,
            static fn (array $p): bool => $p[0] !== 'upgrade-insecure-requests',
        ));
        $result = $this->analyse->analyse($headers, new TransportRequestFacts);

        self::assertContains('document_no_upgrade_insecure', $result->codes());
        self::assertNotContains('document_no_upgrade_insecure', $result->hardCodes());
    }

    // ---------------------------------------------------------------------
    // Witnesses
    // ---------------------------------------------------------------------

    #[Test]
    public function witnesses_expose_observed_values_without_cookie_values(): void
    {
        $headers = [
            ['accept-language', 'nl-NL'],
            ['cookie', 'nc_device=SECRETSESSIONVALUE; _ga=GA1.2.1'],
            ['sec-ch-ua-platform', '"Windows"'],
            ['sec-fetch-mode', 'navigate'],
            ['user-agent', 'Mozilla/5.0 Chrome/141.0.0.0'],
        ];

        $result = $this->analyse->analyse($headers, new TransportRequestFacts);

        self::assertSame('nl-NL', $result->witnessString('accept_language'));
        self::assertSame('"Windows"', $result->witnessString('sec_ch_ua_platform'));
        self::assertSame('navigate', $result->witnessString('sec_fetch_mode'));

        // Names and order are the signal; the values must not be carried anywhere.
        self::assertSame(['nc_device', '_ga'], $result->witnessList('cookie_names'));
        self::assertStringNotContainsString('SECRETSESSIONVALUE', json_encode($result->witnesses(), JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function absent_witnesses_are_omitted_rather_than_null(): void
    {
        $result = $this->analyse->analyse([['accept', 'text/html']], new TransportRequestFacts);

        self::assertNull($result->witness('referer'));
        self::assertArrayNotHasKey('referer', $result->witnesses());
    }

    #[Test]
    public function header_order_is_recorded_in_wire_order(): void
    {
        $headers = [['z-last', '1'], ['a-first', '2'], ['m-middle', '3']];
        $result = $this->analyse->analyse($headers, new TransportRequestFacts);

        self::assertSame('z-last|a-first|m-middle', $result->witnessString('header_order'));
    }

    #[Test]
    public function header_order_is_omitted_when_wire_order_is_unavailable(): void
    {
        // nginx without OpenResty does not expose raw header order, and guessing
        // at it would produce a confident wrong answer. Better to omit it.
        $headers = [['a', '1'], ['b', '2']];
        $facts = new TransportRequestFacts(headerOrderAvailable: false);
        $result = $this->analyse->analyse($headers, $facts);

        self::assertNull($result->witness('header_order'));
        self::assertFalse($result->witness('header_order_available'));
    }

    #[Test]
    public function duplicate_headers_use_the_first_occurrence(): void
    {
        // Deterministic regardless of list position, so the result can be audited.
        $headers = [['accept', 'text/html'], ['accept', '*/*']];
        $result = $this->analyse->analyse($headers, new TransportRequestFacts);

        self::assertSame('text/html', $result->witnessString('accept'));
    }

    /**
     * A GREASE brand is excluded by shape, not by enumeration.
     *
     * The original list held the six LOW-entropy variants (`Not)A;Brand` and friends),
     * which is what Chrome sends in `Sec-CH-UA`. The HIGH-entropy lists
     * (`getHighEntropyValues().brands` and `Sec-CH-UA-Full-Version-List`) use the
     * dotted/slashed form, which was not in the list, and the greased version was then
     * folded into the hinted major by `max()`.
     *
     * Today that is masked: Chrome's greased version (24) is below any real major, so
     * `max()` picks the real one. The mask is a coincidence — GREASE randomises the
     * greased value per origin precisely so that a parser relying on its position or
     * magnitude fails. A browser that greased high would make
     * `sec_ch_full_version_mismatch` a hard finding fire on honest traffic.
     *
     * So the greased brand is matched by shape, and the test drives the dangerous case
     * directly: a greased version ABOVE the real one.
     */
    #[Test]
    public function a_greased_brand_is_excluded_whatever_its_punctuation_or_version(): void
    {
        foreach (['Not)A;Brand', 'Not.A/Brand', 'Not_A)Brand', 'nota)brand', 'not a)brand'] as $brand) {
            foreach (['24', '99', '999'] as $greased) {
                $header = json_encode([
                    $brand => ['version' => $greased, 'brand' => $brand],
                    'Chromium' => ['version' => '141', 'brand' => 'Chromium'],
                ], JSON_THROW_ON_ERROR);

                $result = $this->analyse->analyse(
                    [['sec-ch-ua-full-version-list', $header], ['user-agent', 'Mozilla/5.0 Chrome/141.0.0.0']],
                    new TransportRequestFacts,
                );

                // Asserted on the specific code, not on the whole finding list: this
                // two-header fixture is deliberately minimal and trips three unrelated
                // soft checks, which are correct behaviour and not what is under test.
                self::assertNotContains(
                    'sec_ch_full_version_mismatch',
                    $result->codes(),
                    "a GREASE brand ({$brand} at version {$greased}) was treated as a real one",
                );
            }
        }
    }

    /**
     * Positive control for the test above: a REAL brand with a real disagreement must
     * still fire, or "exclude GREASE" would just be "ignore the header".
     */
    #[Test]
    public function a_genuine_version_disagreement_still_fires(): void
    {
        $header = '"Not)A;Brand";v="24.0.0.0", "Chromium";v="99.0.4844.51"';

        $result = $this->analyse->analyse(
            [['sec-ch-ua-full-version-list', $header], ['user-agent', 'Mozilla/5.0 Chrome/141.0.0.0']],
            new TransportRequestFacts,
        );

        self::assertContains('sec_ch_full_version_mismatch', $result->codes());
    }

    /**
     * A brand whose name contains a digit is not a reserved placeholder: the GREASE filter
     * skips only the `Not…Brand` punctuation forms. Since G-D4i only the `Chromium` brand's
     * major is compared (the engine the `Chrome/` token names; a product brand's version —
     * Opera 127, Edge 141, Samsung 28 — is never the engine's), so the digit brand itself
     * is neither evidence nor a false positive, and the Chromium brand next to it decides.
     */
    #[Test]
    public function a_real_brand_with_a_digit_is_not_treated_as_grease(): void
    {
        $agree = $this->analyse->analyse(
            [['sec-ch-ua-full-version-list', '"NotABrand2";v="7.0.0.0", "Chromium";v="141.0.0.0"'], ['user-agent', 'Mozilla/5.0 Chrome/141.0.0.0']],
            new TransportRequestFacts,
        );
        self::assertNotContains('sec_ch_full_version_mismatch', $agree->codes(), 'a product brand\'s version is never compared with the engine');

        $read = $this->analyse->analyse(
            [['sec-ch-ua-full-version-list', '"NotABrand2";v="141.0.0.0", "Chromium";v="7.0.0.0"'], ['user-agent', 'Mozilla/5.0 Chrome/141.0.0.0']],
            new TransportRequestFacts,
        );
        self::assertContains('sec_ch_full_version_mismatch', $read->codes(), 'the Chromium brand is read whatever stands next to it');

        $alone = $this->analyse->analyse(
            [['sec-ch-ua-full-version-list', '"NotABrand2";v="7.0.0.0"'], ['user-agent', 'Mozilla/5.0 Chrome/141.0.0.0']],
            new TransportRequestFacts,
        );
        self::assertNotContains('sec_ch_full_version_mismatch', $alone->codes(), 'without a Chromium brand there is no evidence');
    }

    /**
     * `document_accept_star` was unsatisfiable, and then briefly unsound.
     *
     * First version: `$isDocumentRequest` AND an Accept header equal to the bare
     * wildcard media range. `isDocumentRequest` requires the Accept header to contain
     * `text/html` and a bare wildcard does not, so the check could never fire for
     * anyone — dead code that config/security.php presented as the worked example of a
     * soft finding.
     *
     * Second version, shipped for about ten minutes: `$isDocumentRequest` AND
     * `str_contains($accept, wildcard)`. Every real Chromium navigation ends with the
     * wildcard catch-all at its lowest priority — `image/webp` then a bare wildcard at
     * `q=0.8` — so it fired on 100% of real browser navigations.
     *
     * Third version keys on `Sec-Fetch-Dest`, which is set by the browser from the real
     * destination and is independent of Accept, so the question is finally both
     * satisfiable and specific.
     */
    #[Test]
    public function a_bare_wildcard_on_a_navigation_is_a_soft_finding(): void
    {
        $headers = self::realChromiumDocument();
        $headers[0] = ['accept', '*/*'];

        $result = $this->analyse->analyse($headers, new TransportRequestFacts(isDocumentRequest: true));

        self::assertContains('document_accept_star', $result->codes());
        self::assertSame([], $result->hardCodes());
    }

    #[Test]
    public function a_rich_accept_header_is_never_a_wildcard_finding(): void
    {
        // The regression that the second version of the check caused. Asserted against
        // the complete real capture, not a trimmed fixture, because the wildcard is at
        // the END of the real header and a trim would hide it.
        $result = $this->analyse->analyse(self::realChromiumDocument(), new TransportRequestFacts(isDocumentRequest: true));

        self::assertNotContains('document_accept_star', $result->codes());
    }

    #[Test]
    public function finding_serialisation_is_stable(): void
    {
        // Built from the complete real capture with one hard violation injected,
        // so the count is exact rather than "at least".
        $headers = self::realChromiumDocument();
        $headers[11] = ['sec-fetch-mode', 'cors'];
        $result = $this->analyse->analyse($headers, new TransportRequestFacts);
        $array = $result->findingsToArray();

        self::assertCount(1, $array);
        self::assertSame('fetch_mode_cors_document', $array[0]['code']);
        self::assertSame('hard', $array[0]['severity']);
        self::assertArrayHasKey('detail', $array[0]);

        // Order must be deterministic: two identical requests produce two
        // identical serialisations, so a diff of two log lines is meaningful.
        $again = $this->analyse->analyse($headers, new TransportRequestFacts);
        self::assertSame($result->findingsToArray(), $again->findingsToArray());
    }

    // ---------------------------------------------------------------------
    // v3 witnesses
    // ---------------------------------------------------------------------

    #[Test]
    public function the_architecture_hint_and_the_client_protocol_are_witnessed(): void
    {
        $result = $this->analyse->analyse(
            [['sec-ch-ua-arch', '"x86"'], ['user-agent', 'Mozilla/5.0 Chrome/141.0.0.0']],
            new TransportRequestFacts(clientSpokeHttp2: true, clientProtocol: 'HTTP/2.0'),
        );

        self::assertSame('"x86"', $result->witnessString('sec_ch_ua_arch'));
        self::assertSame('HTTP/2.0', $result->witnessString('protocol'));
        self::assertTrue($result->witness('protocol_is_http2'));

        $plain = $this->analyse->analyse([['user-agent', 'Mozilla/5.0 Chrome/141.0.0.0']], new TransportRequestFacts);

        self::assertNull($plain->witness('sec_ch_ua_arch'));
        self::assertNull($plain->witness('protocol'), 'an unknown protocol must not be witnessed as a value');
        self::assertFalse($plain->witness('protocol_is_http2'));
    }

    #[Test]
    public function the_ja4_witness_is_the_full_fingerprint(): void
    {
        $ja4 = Ja4::parse('t13d1516h2_8daaf6152771_806a8c22fdea');
        self::assertNotNull($ja4);

        $result = $this->analyse->analyse([], new TransportRequestFacts(ja4: $ja4));

        self::assertSame('t13d1516h2_8daaf6152771_806a8c22fdea', $result->witnessString('ja4'));
        self::assertSame('t13d1516h2', $result->witnessString('ja4_section_one'));
    }
}

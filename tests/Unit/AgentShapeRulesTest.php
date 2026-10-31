<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\CheckRegistry;
use DeviceId\Keys\DeviceComponents;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Rules\TemporalConsistency;
use DeviceId\Scoring\VerdictScorer;
use DeviceId\Support\Config;
use DeviceId\Support\PreviousObservation;
use DeviceId\Support\TransportFinding;
use DeviceId\Support\TransportIntegrityResult;
use DeviceId\Support\TransportRequestFacts;
use DeviceId\Transport\TransportIntegrity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The rules added from the browser-fingerprinting survey (agent-shape inconsistencies, UA shape,
 * the temporal hard-component rule). Each has a firing case, a silent honest-traffic case and the
 * real spoof that must still fire; where a survey claim did not survive a check against the code
 * or a real browser, the test names what was measured instead.
 */
final class AgentShapeRulesTest extends TestCase
{
    private const WINDOWS_CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

    private const MAC_CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

    private const MAC_SAFARI = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15';

    private const ANDROID_CHROME = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36';

    private const ANDROID_WEBVIEW = 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP2A.240805.005; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.7390.54 Mobile Safari/537.36';

    private const SAMSUNG = 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36';

    private const CHROME_MARKS = ['engine' => 'v8', 'errorOwnProps' => 'message,stack', 'stackShape' => 'at', 'internalError' => false];

    private const SAFARI_MARKS = ['engine' => 'jsc', 'errorOwnProps' => 'message,line,column,sourceURL,stack', 'stackShape' => 'at-sign', 'internalError' => false];

    private const CHROMIUM_HINT = ['sec_ch_ua' => '"Chromium";v="141", "Not)A;Brand";v="24"'];

    protected function setUp(): void
    {
        parent::setUp();
        Config::reset();
    }

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    /**
     * @param  array<string, mixed>  $tier2
     * @param  array<string, mixed>  $integrityData
     * @param  array<string, mixed>  $marks
     * @return array<string, mixed>
     */
    private static function claims(string $userAgent = self::WINDOWS_CHROME, array $tier2 = [], array $integrityData = [], array $marks = self::CHROME_MARKS, string $language = 'en-US'): array
    {
        return [
            'tier1' => [
                'environment' => ['state' => 'ok', 'value' => [
                    'identity' => ['userAgent' => $userAgent, 'platform' => 'Win32', 'language' => $language],
                ]],
                'engineIdentity' => ['state' => 'ok', 'value' => $marks],
            ],
            'tier2' => $tier2,
            'integrity' => ['findings' => [], 'data' => $integrityData],
        ];
    }

    /**
     * @param  array<string, mixed>  $claims
     * @param  array<string, string>  $witnesses
     * @return list<string>
     */
    private static function codes(array $claims, array $witnesses = []): array
    {
        $out = [];
        foreach ((new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult([], $witnesses)) as $hit) {
            $out[] = $hit['code'];
        }

        return $out;
    }

    // ------------------------------------------------ notification_permission_nonstandard

    /**
     * @return array<string, array{0: string, 1: string, 2: bool}>
     */
    public static function notificationPairs(): array
    {
        return [
            'headless: query prompt, DOM denied is the OLD rule, not this one' => ['notifications=prompt,camera=prompt', 'denied', false],
            'honest default pair' => ['notifications=prompt,camera=prompt', 'default', false],
            'honest granted pair' => ['notifications=granted', 'granted', false],
            'honest denied pair' => ['notifications=denied', 'denied', false],
            'query rejected with an engine error name' => ['notifications=TypeError,camera=prompt', 'default', false],
            'query rejected, NotSupportedError' => ['notifications=NotSupportedError', 'default', false],
            'query unsupported sentinel' => ['notifications=unsupported', 'default', false],
            'permissions.query answers the DOM word (puppeteer-extra style override)' => ['notifications=default,camera=prompt', 'default', true],
            'permissions.query answers an invented word' => ['notifications=ask', 'default', true],
            'Notification.permission is outside its enum (collector marker)' => ['notifications=prompt', 'invalid', true],
        ];
    }

    #[Test]
    #[DataProvider('notificationPairs')]
    public function an_enumeration_violation_fires_and_an_honest_pair_does_not(string $states, string $permission, bool $expected): void
    {
        $claims = self::claims(tier2: ['permissions' => ['state' => 'ok', 'value' => ['states' => $states, 'notificationPermission' => $permission]]]);

        $this->assertSame($expected, in_array('notification_permission_nonstandard', self::codes($claims), true));
    }

    #[Test]
    public function the_headless_pair_still_fires_its_own_rule_and_a_missing_probe_is_silent(): void
    {
        $headless = self::claims(tier2: ['permissions' => ['state' => 'ok', 'value' => ['states' => 'notifications=prompt', 'notificationPermission' => 'denied']]]);
        $this->assertContains('notification_permission_vs_query', self::codes($headless));
        $this->assertNotContains('notification_permission_nonstandard', self::codes($headless));

        $this->assertNotContains('notification_permission_nonstandard', self::codes(self::claims()));
        $this->assertNotContains('notification_permission_nonstandard', self::codes(self::claims(tier2: ['permissions' => ['state' => 'ok', 'value' => ['supported' => false, 'notificationPermission' => null]]])));
    }

    // ------------------------------------------------ fonts_single_family_desktop

    /**
     * @param  array<string, int>  $faces
     * @return array<string, mixed>
     */
    private static function withFonts(array $faces, string $userAgent = self::WINDOWS_CHROME, array $integrityData = [], array $marks = self::CHROME_MARKS): array
    {
        return self::claims($userAgent, ['fontFaces' => ['state' => 'ok', 'value' => $faces + ['count' => 0, 'windows' => 0, 'mac' => 0, 'linux' => 0, 'android' => 0]]], $integrityData, $marks);
    }

    #[Test]
    public function a_desktop_with_at_most_one_base_font_fires_and_a_real_install_does_not(): void
    {
        // ChatGPT Agent: one Windows family (Calibri). Manus: none.
        $this->assertContains('fonts_single_family_desktop', self::codes(self::withFonts(['count' => 1, 'windows' => 1])));
        $this->assertContains('fonts_single_family_desktop', self::codes(self::withFonts(['count' => 0])));
        $this->assertContains('fonts_single_family_desktop', self::codes(self::withFonts(['count' => 1, 'mac' => 1], self::MAC_CHROME)));

        // A real Windows and a real Mac load most of the ten.
        $this->assertNotContains('fonts_single_family_desktop', self::codes(self::withFonts(['count' => 8, 'windows' => 8])));
        $this->assertNotContains('fonts_single_family_desktop', self::codes(self::withFonts(['count' => 7, 'mac' => 7], self::MAC_CHROME)));
        $this->assertNotContains('fonts_single_family_desktop', self::codes(self::withFonts(['count' => 2, 'windows' => 2])));
        // Linux is out of scope: a Linux box with one font is plausible.
        $this->assertNotContains('fonts_single_family_desktop', self::codes(self::withFonts(['count' => 1, 'linux' => 1], 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36')));
    }

    #[Test]
    public function the_font_rule_is_silent_for_webkit_for_privacy_modes_and_for_a_missing_probe(): void
    {
        $few = ['count' => 0];
        $this->assertNotContains('fonts_single_family_desktop', self::codes(self::withFonts($few, self::MAC_SAFARI, [], self::SAFARI_MARKS)));
        $this->assertNotContains('fonts_single_family_desktop', self::codes(self::withFonts($few, self::WINDOWS_CHROME, ['resistance' => ['state' => 'ok', 'value' => ['brave' => true]]])));

        $firefox = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0';
        $gecko = ['engine' => 'spidermonkey', 'errorOwnProps' => 'columnNumber,fileName,lineNumber,message', 'stackShape' => 'at-sign', 'internalError' => true];
        $this->assertContains('fonts_single_family_desktop', self::codes(self::withFonts($few, $firefox, [], $gecko)));
        $this->assertNotContains('fonts_single_family_desktop', self::codes(self::withFonts($few, $firefox, ['resistance' => ['state' => 'ok', 'value' => ['rfp' => true]]], $gecko)));

        $this->assertNotContains('fonts_single_family_desktop', self::codes(self::claims()));
    }

    #[Test]
    public function the_older_wrong_os_font_rule_still_fires_next_to_it(): void
    {
        $codes = self::codes(self::withFonts(['count' => 5, 'mac' => 5]));

        $this->assertContains('fonts_vs_ua_os', $codes);
        $this->assertNotContains('fonts_single_family_desktop', $codes);
    }

    // ------------------------------------------------ tz_utc_vs_language_region

    /**
     * @return array<string, mixed>
     */
    private static function withZone(string $zone, string $language = 'nl-NL', array $integrityData = []): array
    {
        return self::claims(self::WINDOWS_CHROME, ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['timeZone' => $zone]]]], $integrityData, language: $language);
    }

    #[Test]
    public function utc_with_a_country_language_fires_and_ordinary_pairs_do_not(): void
    {
        $this->assertContains('tz_utc_vs_language_region', self::codes(self::withZone('UTC')));
        $this->assertContains('tz_utc_vs_language_region', self::codes(self::withZone('Etc/UTC', 'en-GB')));

        $this->assertNotContains('tz_utc_vs_language_region', self::codes(self::withZone('Europe/Amsterdam')));
        $this->assertNotContains('tz_utc_vs_language_region', self::codes(self::withZone('UTC', 'en')), 'a bare language names no country');
        $this->assertNotContains('tz_utc_vs_language_region', self::codes(self::withZone('UTC', 'zh-Hans')), 'a script subtag is not a region');
        $this->assertSame(6, EnvironmentConsistency::weights()['tz_utc_vs_language_region']);
    }

    #[Test]
    public function the_accept_language_header_wins_and_resist_fingerprinting_is_silent(): void
    {
        $this->assertContains('tz_utc_vs_language_region', self::codes(self::withZone('UTC', 'en'), ['accept_language' => 'nl-NL,nl;q=0.9']));
        $this->assertNotContains('tz_utc_vs_language_region', self::codes(self::withZone('UTC', 'nl-NL'), ['accept_language' => 'en']));

        // RFP and Tor pin the zone to UTC and the language to en-US by design.
        $this->assertNotContains('tz_utc_vs_language_region', self::codes(self::withZone('UTC', 'en-US', ['resistance' => ['state' => 'ok', 'value' => ['rfp' => true]]])));
    }

    // ------------------------------------------------ ua_reduced_shape_violation / webview_ua_shape

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function reducedUserAgents(): array
    {
        return [
            'Chrome on Windows 10/11 (frozen NT 10.0)' => [self::WINDOWS_CHROME, false],
            'Chrome on a Mac (frozen 10_15_7)' => [self::MAC_CHROME, false],
            'Chrome on Android (frozen 10; K)' => [self::ANDROID_CHROME, false],
            'Android WebView keeps its model and build by design' => [self::ANDROID_WEBVIEW, false],
            'Samsung Internet is Chromium with the model kept' => [self::SAMSUNG, false],
            'Chrome 109 is before the reduction' => ['Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36', false],
            'a pasted Windows 7 UA claiming Chrome 141' => ['Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', true],
            'a pasted old Mac UA' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', true],
            'a pasted Android UA with a model and a real version' => ['Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36', true],
            'a pasted Android UA with the frozen version but a model' => ['Mozilla/5.0 (Linux; Android 10; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36', true],
        ];
    }

    #[Test]
    #[DataProvider('reducedUserAgents')]
    public function the_reduced_user_agent_shape_is_enforced_for_plain_chrome_only(string $userAgent, bool $expected): void
    {
        $this->assertSame($expected, in_array('ua_reduced_shape_violation', self::codes(self::claims($userAgent), self::CHROMIUM_HINT), true));
    }

    #[Test]
    public function the_reduced_shape_rule_needs_the_chromium_header_and_the_weight_stays_inside_the_invariant(): void
    {
        $spoof = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

        $this->assertNotContains('ua_reduced_shape_violation', self::codes(self::claims($spoof)), 'no Sec-CH-UA: the client is not shown to be Chromium');
        $this->assertNotContains('ua_reduced_shape_violation', self::codes(self::claims($spoof), ['sec_ch_ua' => '  ']));
        $this->assertSame(15, EnvironmentConsistency::weights()['ua_reduced_shape_violation']);
    }

    #[Test]
    public function a_webview_without_a_model_and_build_fires_and_a_real_one_does_not(): void
    {
        $this->assertNotContains('webview_ua_shape', self::codes(self::claims(self::ANDROID_WEBVIEW)));
        $this->assertNotContains('webview_ua_shape', self::codes(self::claims('Mozilla/5.0 (Linux; Android 9; SM-G960F Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36')));
        $this->assertNotContains('webview_ua_shape', self::codes(self::claims(self::ANDROID_CHROME)), 'not a WebView at all');

        foreach ([
            'Mozilla/5.0 (Linux; Android 10; K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 14; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36',
        ] as $fabricated) {
            $this->assertContains('webview_ua_shape', self::codes(self::claims($fabricated)), $fabricated);
        }
    }

    #[Test]
    public function every_new_environment_rule_is_registered_with_a_description_and_no_single_check_can_block(): void
    {
        $weights = ['notification_permission_nonstandard' => 25, 'fonts_single_family_desktop' => 10, 'tz_utc_vs_language_region' => 6, 'ua_reduced_shape_violation' => 15, 'webview_ua_shape' => 8,
            'transport_temporal_hard_component_changed' => 25, 'transport_fetch_none_with_referer' => 8, 'transport_referer_implausible' => 8, 'transport_agent_self_identified' => 0];

        foreach ($weights as $code => $weight) {
            $this->assertSame($weight, EnvironmentConsistency::weights()[$code], $code);
            $this->assertSame($weight, CheckRegistry::describe()[$code]['default_weight'], $code);
            $this->assertNotSame('', CheckRegistry::descriptionOf($code), $code);
            if (! str_starts_with($code, 'transport_')) {
                $this->assertContains($code, (new EnvironmentConsistency)->ruleCodes(), $code);
            }
        }
        $this->assertLessThanOrEqual(45, max(EnvironmentConsistency::weights()));
    }

    // ------------------------------------------------ transport: Referer and agent headers

    /**
     * A Chromium document request, as `TransportIntegrityTest::realChromiumDocument()` captured it, with the three
     * headers under test replaced.
     *
     * @return list<array{0: string, 1: string}>
     */
    private static function request(string $site, ?string $referer, string $host = 'www.example.nl', string $userAgent = self::WINDOWS_CHROME, array $extra = []): array
    {
        $headers = [
            ['host', $host],
            ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'],
            ['accept-encoding', 'gzip, deflate, br'],
            ['accept-language', 'nl-NL,nl;q=0.9'],
            ['sec-ch-ua', '"Chromium";v="141", "Not)A;Brand";v="24"'],
            ['sec-ch-ua-mobile', '?0'],
            ['sec-ch-ua-platform', '"Windows"'],
            ['sec-fetch-dest', 'document'],
            ['sec-fetch-mode', 'navigate'],
            ['sec-fetch-site', $site],
            ['sec-fetch-user', '?1'],
            ['upgrade-insecure-requests', '1'],
            ['user-agent', $userAgent],
        ];
        if ($referer !== null) {
            $headers[] = ['referer', $referer];
        }

        return [...$headers, ...$extra];
    }

    /**
     * @param  list<array{0: string, 1: string}>  $headers
     * @return list<string>
     */
    private static function transportCodes(array $headers, bool $clientFrame = true): array
    {
        return (new TransportIntegrity)->analyse($headers, new TransportRequestFacts(headersAreClientFrame: $clientFrame))->codes();
    }

    #[Test]
    public function honest_referer_shapes_measured_in_real_browsers_are_silent(): void
    {
        // Measured on Chromium 153, Firefox 155 and WebKit 26.6 (Playwright 1.63): a typed address
        // has no Referer; a cross-site click carries the origin; a same-origin link carries the page.
        $this->assertSame([], self::transportCodes(self::request('none', null)));
        $this->assertSame([], self::transportCodes(self::request('cross-site', 'https://www.google.com/')));
        $this->assertSame([], self::transportCodes(self::request('same-origin', 'https://www.example.nl/pagina')));
        $this->assertSame([], self::transportCodes(self::request('same-origin', 'https://WWW.EXAMPLE.NL/pagina', 'www.example.nl:443')), 'host case and port do not matter');
    }

    #[Test]
    public function a_third_party_referer_on_a_same_origin_request_fires_only_where_the_headers_are_the_clients_own(): void
    {
        $spoof = self::request('same-origin', 'https://evil.example/landing');

        $this->assertContains('referer_implausible', self::transportCodes($spoof));
        $this->assertNotContains('referer_implausible', self::transportCodes($spoof, clientFrame: false), 'behind a proxy that rewrites Host, every request would judge the proxy');
        $this->assertNotContains('referer_implausible', self::transportCodes(self::request('same-origin', 'https://evil.example/', host: '')), 'an absent Host is no evidence');
    }

    #[Test]
    public function safari_keeps_the_old_referrer_on_reload_so_it_is_never_judged_by_the_same_origin_test(): void
    {
        // Measured on WebKit 26.6: reloading a page reached from another origin sends
        // Sec-Fetch-Site: same-origin together with the ORIGINAL cross-origin Referer. The survey
        // called this combination impossible ("FP ~ 0"); it is not, in WebKit.
        $reload = self::request('same-origin', 'http://127.0.0.1:8101/', host: 'localhost:8102', userAgent: self::MAC_SAFARI);

        $this->assertNotContains('referer_implausible', self::transportCodes($reload));
        // The same headers from a Chromium User-Agent are the implausible shape.
        $this->assertContains('referer_implausible', self::transportCodes(self::request('same-origin', 'http://127.0.0.1:8101/', host: 'localhost:8102')));
        // iOS Chrome is WebKit.
        $this->assertNotContains('referer_implausible', self::transportCodes(self::request('same-origin', 'https://other.example/', userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1')));
    }

    #[Test]
    public function a_user_started_navigation_carrying_a_web_referer_fires_and_embedders_are_excused(): void
    {
        // `page.goto(url, { referer })` on Chromium 153, Firefox 155 and WebKit 26.6 sent Sec-Fetch-Site: none with that Referer.
        $this->assertContains('fetch_none_with_referer', self::transportCodes(self::request('none', 'https://evil.example/')));
        // A Custom Tab opened by an app sends its android-app:// referrer, and a WebView's embedder adds headers.
        $this->assertNotContains('fetch_none_with_referer', self::transportCodes(self::request('none', 'android-app://com.google.android.gm')));
        $this->assertNotContains('fetch_none_with_referer', self::transportCodes(self::request('none', 'https://app.example/', userAgent: self::ANDROID_WEBVIEW)));
        $this->assertNotContains('fetch_none_with_referer', self::transportCodes(self::request('none', 'https://www.google.com/', userAgent: self::MAC_SAFARI)));
        // The old premise (Sec-Fetch-Mode: none) names a value the fetch standard does not define; it is no longer the trigger.
        $mode = self::request('cross-site', 'https://www.google.com/');
        $mode[8] = ['sec-fetch-mode', 'none'];
        $this->assertNotContains('fetch_none_with_referer', self::transportCodes($mode));
    }

    #[Test]
    public function an_agent_that_signs_its_requests_is_labelled_at_weight_zero_and_never_scored(): void
    {
        $signed = self::request('none', null, extra: [['signature-agent', '"https://chatgpt.com"'], ['signature-input', 'sig1=("@authority");created=1'], ['signature', 'sig1=:abc=:']]);

        $result = (new TransportIntegrity)->analyse($signed, new TransportRequestFacts);
        $this->assertContains('agent_self_identified', $result->codes());
        foreach ($result->findings as $finding) {
            $this->assertFalse($finding->isHard());
            $this->assertStringNotContainsString('chatgpt', $finding->detail, 'the detail names headers, never their values');
        }

        $verdict = (new VerdictScorer(new EnvironmentConsistency))->score([], $result);
        $this->assertSame([], array_values(array_diff($verdict->reasons, ['transport_agent_self_identified'])), 'nothing else fires');
        $this->assertSame(0, $verdict->score);
        $this->assertSame('pass', $verdict->band);
        $this->assertContains('transport_agent_self_identified', $verdict->reasons, 'logged for the operator');

        // Either form alone is enough; the pair `Signature` + `Signature-Input` without Signature-Agent too; a lone `Signature` is not.
        $this->assertContains('agent_self_identified', self::transportCodes(self::request('none', null, extra: [['signature-agent', '"x"']])));
        $this->assertContains('agent_self_identified', self::transportCodes(self::request('none', null, extra: [['signature', 'a'], ['signature-input', 'b']])));
        $this->assertNotContains('agent_self_identified', self::transportCodes(self::request('none', null, extra: [['signature', 'a']])));
        $this->assertNotContains('agent_self_identified', self::transportCodes(self::request('none', null)));
    }

    // ------------------------------------------------ temporal_hard_component_changed

    #[Test]
    public function a_changed_hard_tuple_fires_and_an_unchanged_or_unknown_one_does_not(): void
    {
        $rule = new TemporalConsistency;
        $windows = hash('sha256', 'windows|x86|0');
        $android = hash('sha256', 'android|arm|1');

        $changed = $rule->findings(new PreviousObservation(blockTuple: $windows), null, null, $android);
        $this->assertSame([TemporalConsistency::HARD_COMPONENT_CHANGED], array_map(static fn (TransportFinding $f): string => $f->code, $changed));
        $this->assertFalse($changed[0]->isHard());

        $this->assertSame([], $rule->findings(new PreviousObservation(blockTuple: $windows), null, null, $windows));
        $this->assertSame([], $rule->findings(new PreviousObservation(blockTuple: $windows), null, null, null), 'a hard component unknown now');
        $this->assertSame([], $rule->findings(new PreviousObservation(blockTuple: null), null, null, $android), 'unknown before');
        $this->assertSame([], $rule->findings(new PreviousObservation(blockTuple: ''), null, null, $android));
        $this->assertSame([], $rule->findings(null, null, null, $android), 'a first visit');
        $this->assertSame([], $rule->findings(new PreviousObservation(blockTuple: $windows), null, null), 'a host that does not pass the tuple');
    }

    #[Test]
    public function a_changed_soft_component_is_not_a_hard_change_and_the_ja4_rule_is_unaffected(): void
    {
        // Negative control from the survey: comparing SOFT components would fire on an honest font install.
        // The rule sees only the block tuple, which hashes os|arch|touch and nothing soft.
        $this->assertSame(['os', 'arch', 'touch'], DeviceComponents::HARD);
        $same = DeviceComponents::blockTuple(['os' => 'windows', 'arch' => 'x86', 'touch' => 0, 'fonts' => 'aaaa']);
        $afterFontInstall = DeviceComponents::blockTuple(['os' => 'windows', 'arch' => 'x86', 'touch' => 0, 'fonts' => 'bbbb', 'cores' => 8]);
        $this->assertNotNull($same);
        $this->assertSame($same, $afterFontInstall);
        $this->assertSame([], (new TemporalConsistency)->findings(new PreviousObservation(blockTuple: $same), null, null, $afterFontInstall));

        $changedOs = DeviceComponents::blockTuple(['os' => 'macos', 'arch' => 'arm', 'touch' => 0]);
        $this->assertCount(1, (new TemporalConsistency)->findings(new PreviousObservation(blockTuple: $same), null, null, $changedOs));

        $ja4 = (new TemporalConsistency)->findings(
            new PreviousObservation('t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb', 'chrome-141-windows'),
            new TransportIntegrityResult([], ['ja4' => 't13d1715h2_cccccccccccc_dddddddddddd']),
            'chrome-141-windows',
        );
        $this->assertSame([TemporalConsistency::JA4_CHANGED_WITHOUT_UA_CHANGE], array_map(static fn (TransportFinding $f): string => $f->code, $ja4));
    }
}

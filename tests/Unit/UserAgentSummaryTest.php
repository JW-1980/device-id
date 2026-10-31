<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Support\UserAgentSummary;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The reason this class exists is entropy reduction, so the tests are built
 * around that rather than around detection accuracy: the nesting cases (Edge
 * and Opera both announce themselves as Chrome, every Chromium announces
 * itself as Safari) are the ones that actually break, and the entropy
 * assertions pin the property a future "let's make detection better" change
 * would quietly destroy.
 */
class UserAgentSummaryTest extends TestCase
{
    private const CHROME_WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36';

    private const EDGE_WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.83';

    private const SAFARI_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15';

    /**
     * @return array<string, array{string, string}>
     */
    public static function browserCases(): array
    {
        return [
            'chrome on windows' => [self::CHROME_WINDOWS, 'Chrome 121 on Windows'],
            'safari on macos' => [self::SAFARI_MAC, 'Safari 17 on macOS'],
            'firefox on linux' => [
                'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
                'Firefox 122 on Linux',
            ],
            'chrome on android' => [
                'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36',
                'Chrome 121 on Android',
            ],
            'chrome on ios reports CriOS' => [
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/121.0.6167.66 Mobile/15E148 Safari/604.1',
                'Chrome 121 on iOS',
            ],
            'safari on ios' => [
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
                'Safari 17 on iOS',
            ],
            'chromeos' => [
                'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                'Chrome 121 on ChromeOS',
            ],
        ];
    }

    #[DataProvider('browserCases')]
    public function test_it_summarises_mainstream_clients(string $userAgent, string $expected): void
    {
        $this->assertSame($expected, UserAgentSummary::summarize($userAgent));
    }

    /**
     * Edge sends BOTH "Chrome/121" and "Safari/537.36" in the same header.
     * Checked in the wrong order it is reported as Chrome, which would make
     * the audit trail quietly wrong for a large share of corporate admins.
     */
    public function test_edge_is_not_mistaken_for_chrome_or_safari(): void
    {
        $this->assertSame('Edge 121 on Windows', UserAgentSummary::summarize(self::EDGE_WINDOWS));
    }

    public function test_opera_is_not_mistaken_for_chrome(): void
    {
        $this->assertSame('Opera 106 on Windows', UserAgentSummary::summarize(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.4998.70'
        ));
    }

    public function test_samsung_internet_is_not_mistaken_for_chrome(): void
    {
        $this->assertSame('Samsung Internet 23 on Android', UserAgentSummary::summarize(
            'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36'
        ));
    }

    /**
     * Android UA strings contain "Linux", and iOS ones contain "like Mac OS X".
     * Both would be mislabelled by a naive OS check.
     */
    public function test_android_is_not_reported_as_linux_and_ios_is_not_reported_as_macos(): void
    {
        $this->assertStringEndsWith('on Android', (string) UserAgentSummary::summarize(
            'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36'
        ));
        $this->assertStringEndsWith('on iOS', (string) UserAgentSummary::summarize(
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
        ));
    }

    /**
     * THE POINT OF THE CLASS. Two builds that a device detector would happily
     * tell apart must land in one bucket here. A change that "improved"
     * detection by keeping the minor version, the build number or the device
     * model would fail this — correctly, because it would have restored the
     * fingerprint the summary exists to remove.
     */
    public function test_different_builds_of_one_browser_version_collapse_to_one_value(): void
    {
        $a = UserAgentSummary::summarize('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36');
        $b = UserAgentSummary::summarize('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.184 Safari/537.36');

        $this->assertSame($a, $b);
    }

    /**
     * The OS version is dropped entirely: Windows 10 and Windows 11 admins are
     * one bucket. Keeping it would add identifying detail without answering
     * any question an audit trail asks.
     */
    public function test_os_version_is_not_retained(): void
    {
        $win10 = UserAgentSummary::summarize('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36');
        $win11 = UserAgentSummary::summarize('Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36');

        $this->assertSame('Chrome 121 on Windows', $win10);
        // Two OS versions, one bucket — asserted directly rather than by
        // string-searching the output, which could pass for the wrong reason
        // (the browser's own major version is a digit too).
        $this->assertSame($win10, $win11);
    }

    /**
     * A major version bump must still be visible — it is the one detail worth
     * acting on (an admin session from a years-old build).
     */
    public function test_major_version_is_retained(): void
    {
        $this->assertNotSame(
            UserAgentSummary::summarize('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.0.0 Safari/537.36'),
            UserAgentSummary::summarize('Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'),
        );
    }

    /**
     * An absent header is a real, distinguishable state and is reported as
     * such — not as an unknown browser, which would merge "no header sent"
     * with "header we could not parse" (CLAUDE.md G3: states are never
     * merged).
     */
    public function test_absent_header_is_null_not_unknown(): void
    {
        $this->assertNull(UserAgentSummary::summarize(null));
        $this->assertNull(UserAgentSummary::summarize(''));
        $this->assertNull(UserAgentSummary::summarize('   '));
    }

    public function test_unrecognised_client_is_reported_as_unknown_rather_than_guessed(): void
    {
        $this->assertSame('Unknown browser on Unknown OS', UserAgentSummary::summarize('curl/8.4.0'));
    }

    /**
     * Half-recognised input reports the half it established and no more.
     */
    public function test_a_recognised_os_with_an_unrecognised_browser_reports_both_honestly(): void
    {
        $this->assertSame('Unknown browser on Windows', UserAgentSummary::summarize(
            'SomeInternalTool/2.0 (Windows NT 10.0)'
        ));
    }

    /**
     * The header is attacker-controlled and unbounded. A very long string must
     * not be scanned in full, and must not blow up.
     */
    public function test_an_oversized_header_is_bounded_and_still_returns_a_string(): void
    {
        $summary = UserAgentSummary::summarize(str_repeat('A', 50_000).' Chrome/121.0.0.0');

        $this->assertIsString($summary);
        // The Chrome token sits beyond the scan window, so it is NOT found —
        // which is the intended trade: bounded work over complete detection on
        // hostile input.
        $this->assertSame('Unknown browser on Unknown OS', $summary);
    }

    /**
     * Whatever the input, the output must stay inside the small set of buckets
     * this class defines — that is the entropy guarantee the audit trail
     * relies on.
     */
    public function test_output_never_echoes_the_raw_header_back(): void
    {
        $hostile = 'Mozilla/5.0 (secret-token-abc123; Chrome/121.0.0.0) Windows';
        $summary = (string) UserAgentSummary::summarize($hostile);

        $this->assertStringNotContainsString('secret-token-abc123', $summary);
        $this->assertSame('Chrome 121 on Windows', $summary);
    }
}

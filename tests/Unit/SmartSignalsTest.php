<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\CheckRegistry;
use DeviceId\Model\FeatureCatalogue;
use DeviceId\Network\NetworkFacts;
use DeviceId\Reputation\ReputationResult;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Signals\SmartSignals;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The smart signals: IP country against locale, virtual machines and emulators, private
 * browsing. Each has a case that fires, a case that is honest-silent (the traveller, the expat,
 * the Linux software-rendering user, the Firefox visitor in a normal profile) and a case that is
 * partly spoofed and must still fire.
 */
final class SmartSignalsTest extends TestCase
{
    private const WINDOWS_CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

    private const MAC_CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

    private const LINUX_FIREFOX = 'Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0';

    private const SAFARI = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15';

    private const ANDROID = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36';

    private const V8 = ['engine' => 'v8', 'errorOwnProps' => 'message,stack', 'stackShape' => 'at', 'internalError' => false];

    private const SPIDERMONKEY = ['engine' => 'spidermonkey', 'errorOwnProps' => 'message,stack,fileName,lineNumber,columnNumber', 'stackShape' => 'at-sign', 'internalError' => true];

    private const JSC = ['engine' => 'jsc', 'errorOwnProps' => 'message,line,column,sourceURL', 'stackShape' => 'at-sign', 'internalError' => false];

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
     * @param  array<string, mixed>  $identity
     * @param  array<string, mixed>  $tier2
     * @param  array<string, mixed>  $marks
     * @return array<string, mixed>
     */
    private static function claims(string $ua = self::WINDOWS_CHROME, array $identity = [], array $tier2 = [], array $marks = self::V8, array $screen = ['width' => 1920, 'height' => 1080]): array
    {
        return [
            'tier1' => [
                'environment' => ['state' => 'ok', 'value' => [
                    'identity' => array_merge(['userAgent' => $ua, 'platform' => 'Win32', 'maxTouchPoints' => 0, 'language' => 'nl-NL', 'languages' => ['nl-NL', 'nl']], $identity),
                    'screen' => $screen,
                ]],
                'engineIdentity' => ['state' => 'ok', 'value' => $marks],
            ],
            'tier2' => $tier2 + ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'nl-NL', 'timeZone' => 'Europe/Amsterdam']]]],
            'integrity' => ['findings' => [], 'data' => []],
        ];
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, string>
     */
    private static function fired(array $claims, ?NetworkFacts $network = null): array
    {
        $out = [];
        foreach ((new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult, $network) as $hit) {
            $out[$hit['code']] = $hit['detail'];
        }

        return $out;
    }

    private static function gpu(string $renderer, string $vendor = 'Google Inc.'): array
    {
        return ['gpu' => ['state' => 'ok', 'value' => ['webgl' => ['renderer' => $renderer, 'vendor' => $vendor]]]];
    }

    // ------------------------------------------------------------------ IP country against locale

    #[Test]
    public function the_locale_rule_fires_only_when_the_time_zone_and_the_languages_both_disagree(): void
    {
        $inSpain = new NetworkFacts(NetworkFacts::STATE_OK, 'ES');
        $inNetherlands = new NetworkFacts(NetworkFacts::STATE_OK, 'NL');

        $this->assertArrayHasKey('ip_country_vs_locale', self::fired(self::claims(), $inSpain), 'a Dutch clock and Dutch languages from a Spanish address');
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired(self::claims(), $inNetherlands));
        $this->assertSame(5, EnvironmentConsistency::weights()['ip_country_vs_locale']);

        // The expat: foreign language everywhere, local clock. One disagreement, silent.
        $expat = self::claims(identity: ['language' => 'en-US', 'languages' => ['en-US', 'en']], tier2: ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'en-US', 'timeZone' => 'Europe/Amsterdam']]]]);
        $this->assertSame(['timezone' => false, 'language' => true], SmartSignals::localeAgainstCountry($expat, $inNetherlands));
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired($expat, $inNetherlands));

        // The traveller who changed the clock but kept a home-country language list that includes the host country's.
        $traveller = self::claims(identity: ['language' => 'nl-NL', 'languages' => ['nl-NL', 'es-ES']]);
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired($traveller, $inSpain));
    }

    #[Test]
    public function the_locale_rule_is_silent_without_evidence(): void
    {
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired(self::claims()), 'no network facts at all');
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired(self::claims(), NetworkFacts::unknown()), 'unknown is not a mismatch');
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired(self::claims(identity: ['language' => 'nl', 'languages' => ['nl']], tier2: ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'nl', 'timeZone' => 'Europe/Amsterdam']]]]), new NetworkFacts(NetworkFacts::STATE_OK, 'BE')), 'a bare language has no region to compare');
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired(self::claims(tier2: ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'nl-NL', 'timeZone' => 'Antarctica/Troll']]]]), new NetworkFacts(NetworkFacts::STATE_OK, 'ES')), 'an unlisted zone is silent');
        // UTC and en-US from a protected Firefox: the rule must not fire on resistFingerprinting.
        $rfp = self::claims(self::LINUX_FIREFOX, ['language' => 'en-US', 'languages' => ['en-US']], ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'en-US', 'timeZone' => 'UTC']]]], self::SPIDERMONKEY);
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired($rfp, new NetworkFacts(NetworkFacts::STATE_OK, 'DE')));
    }

    #[Test]
    public function a_registration_country_that_names_the_visitors_country_keeps_the_locale_rule_silent(): void
    {
        // The routing data places the block in Germany, the ASN is registered in the Netherlands:
        // a Dutch clock and Dutch languages agree with one of the two countries.
        $routedElsewhere = new NetworkFacts(NetworkFacts::STATE_OK, 'DE', registrationCountry: 'NL');

        $this->assertSame(['timezone' => false, 'language' => false], SmartSignals::localeAgainstCountry(self::claims(), $routedElsewhere));
        $this->assertArrayNotHasKey('ip_country_vs_locale', self::fired(self::claims(), $routedElsewhere));
        $this->assertArrayHasKey('ip_country_vs_locale', self::fired(self::claims(), new NetworkFacts(NetworkFacts::STATE_OK, 'DE', registrationCountry: 'FR')), 'both countries differ from the visitor: still the signal');
        $this->assertArrayHasKey('ip_country_vs_locale', self::fired(self::claims(), new NetworkFacts(NetworkFacts::STATE_OK, 'DE')), 'no second opinion: the single-country rule as before');
    }

    #[Test]
    public function a_second_country_can_only_make_the_locale_rule_quieter_never_noisier(): void
    {
        $visitors = [
            'dutch' => self::claims(),
            'expat' => self::claims(identity: ['language' => 'en-US', 'languages' => ['en-US', 'en']], tier2: ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'en-US', 'timeZone' => 'Europe/Amsterdam']]]]),
            'german' => self::claims(identity: ['language' => 'de-DE', 'languages' => ['de-DE']], tier2: ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'de-DE', 'timeZone' => 'Europe/Berlin']]]]),
            'bare' => self::claims(identity: ['language' => 'nl', 'languages' => ['nl']], tier2: ['intl' => ['state' => 'ok', 'value' => ['resolved' => ['locale' => 'nl', 'timeZone' => 'Europe/Amsterdam']]]]),
        ];
        $countries = ['NL', 'BE', 'DE', 'US', 'FR', 'ES'];

        foreach ($visitors as $name => $claims) {
            foreach ($countries as $routing) {
                $alone = SmartSignals::localeAgainstCountry($claims, new NetworkFacts(NetworkFacts::STATE_OK, $routing));
                foreach ([null, ...$countries] as $registration) {
                    $both = SmartSignals::localeAgainstCountry($claims, new NetworkFacts(NetworkFacts::STATE_OK, $routing, registrationCountry: $registration));
                    foreach (['timezone', 'language'] as $setting) {
                        $this->assertFalse($both[$setting] === true && $alone[$setting] !== true, "{$name} routed {$routing} registered ".($registration ?? 'none').": {$setting} became noisier");
                        $this->assertSame($alone[$setting] === null, $both[$setting] === null, 'a second country never changes whether a setting can be checked');
                    }
                }
            }
        }
    }

    #[Test]
    public function the_feature_for_locale_disagreements_follows_the_same_quieter_rule(): void
    {
        $routedElsewhere = new NetworkFacts(NetworkFacts::STATE_OK, 'DE', registrationCountry: 'NL');

        $this->assertSame([], SmartSignals::features(self::claims(), $routedElsewhere));
        $this->assertSame(['sig_locale_disagreements' => 2.0], SmartSignals::features(self::claims(), new NetworkFacts(NetworkFacts::STATE_OK, 'DE')));
    }

    #[Test]
    public function a_spoofed_user_agent_does_not_hide_a_locale_mismatch(): void
    {
        $spoofed = self::claims(self::MAC_CHROME, ['platform' => 'MacIntel']);

        $this->assertArrayHasKey('ip_country_vs_locale', self::fired($spoofed, new NetworkFacts(NetworkFacts::STATE_OK, 'US')), 'the rule reads the clock and the languages, not the User-Agent');
    }

    // ------------------------------------------------------------------ network category

    #[Test]
    public function hosting_and_vpn_networks_fire_softly_and_exclusively(): void
    {
        $hosting = new NetworkFacts(NetworkFacts::STATE_OK, 'NL', 14061, NetworkFacts::CATEGORY_HOSTING);
        $vpn = new NetworkFacts(NetworkFacts::STATE_OK, 'NL', 218799, NetworkFacts::CATEGORY_VPN, true);
        $residential = new NetworkFacts(NetworkFacts::STATE_OK, 'NL', 1136);

        $this->assertSame(['network_hosting'], array_values(array_intersect(array_keys(self::fired(self::claims(), $hosting)), ['network_hosting', 'network_vpn'])));
        $this->assertSame(['network_vpn'], array_values(array_intersect(array_keys(self::fired(self::claims(), $vpn)), ['network_hosting', 'network_vpn'])), 'a VPN ASN in a cloud range pays once');
        $this->assertSame([], array_values(array_intersect(array_keys(self::fired(self::claims(), $residential)), ['network_hosting', 'network_vpn'])));
        $this->assertSame([], array_values(array_intersect(array_keys(self::fired(self::claims(), NetworkFacts::unknown())), ['network_hosting', 'network_vpn'])), 'no data is not clean and not listed');
        $this->assertSame([5, 4], [EnvironmentConsistency::weights()['network_hosting'], EnvironmentConsistency::weights()['network_vpn']]);
    }

    #[Test]
    public function a_published_cloud_range_counts_as_hosting_and_a_forged_client_cannot_clear_it(): void
    {
        $cloud = (new NetworkFacts(NetworkFacts::STATE_OK, 'US'))->withReputation(new ReputationResult(ReputationResult::STATE_OK, ['datacenter']));

        $forged = self::claims(self::MAC_CHROME, ['language' => 'en-US', 'languages' => ['en-US']], self::gpu('ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)'));
        $this->assertArrayHasKey('network_hosting', self::fired($forged, $cloud), 'every claim can be forged; the address cannot');
    }

    #[Test]
    public function a_protected_firefox_is_not_scored_for_its_network_and_a_plain_one_is(): void
    {
        $vpn = new NetworkFacts(NetworkFacts::STATE_OK, 'SE', 1, NetworkFacts::CATEGORY_VPN);
        $plain = self::claims(self::LINUX_FIREFOX, [], [], self::SPIDERMONKEY);
        // Mullvad Browser and Tor Browser users are the honest majority behind VPN addresses.
        $protected = $plain;
        $protected['integrity']['data']['resistance'] = ['rfp' => true, 'tor' => false];

        $this->assertArrayHasKey('network_vpn', self::fired($plain, $vpn), 'a plain Firefox on a VPN address is scored');
        $this->assertArrayNotHasKey('network_vpn', self::fired($protected, $vpn));
        $this->assertArrayNotHasKey('network_hosting', self::fired($protected, new NetworkFacts(NetworkFacts::STATE_OK, 'SE', 1, NetworkFacts::CATEGORY_HOSTING)));
    }

    // ------------------------------------------------------------------ virtual machines

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function renderers(): array
    {
        return [
            'vmware' => ['ANGLE (VMware, VMware SVGA 3D (0x00000405) Direct3D11 vs_5_0 ps_5_0, D3D11)', true],
            'vmware mesa' => ['SVGA3D; build: RELEASE; LLVM;', true],
            'virtualbox' => ['VirtualBox Graphics Adapter', true],
            'parallels' => ['Parallels Display Adapter (WDDM)', true],
            'qemu virtio' => ['virgl (Mesa Virtio-GPU)', true],
            'hyper-v' => ['Microsoft Hyper-V Video', true],
            'a real nvidia' => ['ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)', false],
            'a real intel' => ['ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)', false],
            'windows warp' => ['ANGLE (Microsoft, Microsoft Basic Render Driver Direct3D11 vs_5_0 ps_5_0, D3D11)', false],
            'linux llvmpipe' => ['Mesa/X.org, llvmpipe (LLVM 15.0.7, 256 bits)', false],
        ];
    }

    #[Test]
    #[DataProvider('renderers')]
    public function the_hypervisor_gpu_rule_reads_the_renderer_and_nothing_else(string $renderer, bool $fires): void
    {
        $fired = self::fired(self::claims(tier2: self::gpu($renderer)));

        $this->assertSame($fires, array_key_exists('vm_gpu_renderer', $fired), $renderer);
    }

    #[Test]
    public function the_hypervisor_rule_survives_a_spoofed_user_agent_and_skips_headless_and_touch(): void
    {
        $vmware = self::gpu('ANGLE (VMware, VMware SVGA 3D, D3D11)');

        $this->assertArrayHasKey('vm_gpu_renderer', self::fired(self::claims(self::MAC_CHROME, ['platform' => 'MacIntel'], $vmware)), 'a User-Agent switched to macOS leaves the VMware GPU');
        $this->assertArrayNotHasKey('vm_gpu_renderer', self::fired(self::claims(str_replace('Chrome/', 'HeadlessChrome/', self::WINDOWS_CHROME), [], $vmware)), 'headless is the headless rules\' business');
        $this->assertArrayNotHasKey('vm_gpu_renderer', self::fired(self::claims(self::ANDROID, ['maxTouchPoints' => 5], $vmware)), 'a touch device is not a desktop VM');
        $this->assertSame(5, EnvironmentConsistency::weights()['vm_gpu_renderer']);
    }

    #[Test]
    public function a_software_renderer_alone_is_silent_and_with_a_vm_screen_it_fires(): void
    {
        $llvmpipe = self::gpu('Mesa/X.org, llvmpipe (LLVM 15.0.7, 256 bits)');
        $linux = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

        $this->assertArrayNotHasKey('vm_software_gpu_screen', self::fired(self::claims($linux, tier2: $llvmpipe)), 'the honest Linux desktop without a GPU driver');
        $this->assertArrayNotHasKey('vm_software_gpu_screen', self::fired(self::claims($linux, tier2: $llvmpipe, screen: ['width' => 1366, 'height' => 768])));
        $this->assertArrayNotHasKey('vm_software_gpu_screen', self::fired(self::claims($linux, tier2: self::gpu('ANGLE (NVIDIA, GeForce)'), screen: ['width' => 1024, 'height' => 768])), 'a small screen alone is a small screen');
        $this->assertArrayHasKey('vm_software_gpu_screen', self::fired(self::claims($linux, tier2: $llvmpipe, screen: ['width' => 1024, 'height' => 768])));
        $this->assertSame(4, EnvironmentConsistency::weights()['vm_software_gpu_screen']);
        $this->assertSame(1.0, SmartSignals::features(self::claims($linux, tier2: $llvmpipe))['sig_software_gpu'], 'the model still sees it as a feature');
    }

    // ------------------------------------------------------------------ emulators

    #[Test]
    public function an_android_emulator_fires_and_a_phone_does_not(): void
    {
        $emulatorModel = self::claims(self::ANDROID, ['maxTouchPoints' => 5]);
        $emulatorModel['tier1']['uaClientHints'] = ['state' => 'ok', 'value' => ['high' => ['model' => 'sdk_gphone64_x86_64']]];
        $swiftshader = self::claims(self::ANDROID, ['maxTouchPoints' => 5], self::gpu('ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)'));
        $phone = self::claims(self::ANDROID, ['maxTouchPoints' => 5], self::gpu('Adreno (TM) 740'));
        $oldTokenUa = self::claims('Mozilla/5.0 (Linux; Android 11; Android SDK built for x86) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36', ['maxTouchPoints' => 5]);

        $this->assertArrayHasKey('emulator_android', self::fired($emulatorModel));
        $this->assertArrayHasKey('emulator_android', self::fired($swiftshader));
        $this->assertArrayHasKey('emulator_android', self::fired($oldTokenUa));
        $this->assertArrayNotHasKey('emulator_android', self::fired($phone));
        $this->assertArrayNotHasKey('emulator_android', self::fired(self::claims(tier2: self::gpu('SwiftShader'))), 'software rendering on a desktop is the VM/headless rules\' business');
        $this->assertSame(8, EnvironmentConsistency::weights()['emulator_android']);
    }

    // ------------------------------------------------------------------ private browsing

    /**
     * @param  array<string, mixed>  $profile
     * @return array<string, mixed>
     */
    private static function profile(array $profile): array
    {
        return ['storageProfile' => ['state' => 'ok', 'value' => $profile]];
    }

    #[Test]
    public function private_mode_is_read_per_engine_from_the_measured_signal(): void
    {
        // Measured: Chromium 153 incognito quota 3 GiB (step 23) against a 3.5 GiB heap limit (step 24); normal 10 GiB (step 27).
        $incognito = self::claims(tier2: self::profile(['quotaStep' => 23, 'heapStep' => 24, 'opfs' => 'ok']));
        $normal = self::claims(tier2: self::profile(['quotaStep' => 27, 'heapStep' => 24, 'opfs' => 'ok']));
        $this->assertSame(['likely' => true, 'engine' => 'chromium', 'basis' => 'quota_below_heap', 'confidence' => 'low'], SmartSignals::privateMode($incognito));
        $this->assertFalse(SmartSignals::privateMode($normal)['likely']);
        $this->assertFalse(SmartSignals::privateMode(self::claims(tier2: self::profile(['quotaStep' => 25, 'heapStep' => 24, 'opfs' => 'ok'])))['likely'], 'one step above the heap limit is ambiguous and silent');

        $geckoPrivate = self::claims(self::LINUX_FIREFOX, ['platform' => 'Linux x86_64'], self::profile(['quotaStep' => 27, 'heapStep' => null, 'opfs' => 'security']), self::SPIDERMONKEY);
        $geckoNormal = self::claims(self::LINUX_FIREFOX, ['platform' => 'Linux x86_64'], self::profile(['quotaStep' => 27, 'heapStep' => null, 'opfs' => 'ok']), self::SPIDERMONKEY);
        $this->assertTrue(SmartSignals::privateMode($geckoPrivate)['likely']);
        $this->assertSame('medium', SmartSignals::privateMode($geckoPrivate)['confidence']);
        $this->assertFalse(SmartSignals::privateMode($geckoNormal)['likely']);

        $webkitPrivate = self::claims(self::SAFARI, ['platform' => 'MacIntel'], self::profile(['quotaStep' => 20, 'heapStep' => null, 'opfs' => 'error']), self::JSC);
        $this->assertTrue(SmartSignals::privateMode($webkitPrivate)['likely']);
        $this->assertSame('low', SmartSignals::privateMode($webkitPrivate)['confidence'], 'Safari itself could not be measured');
    }

    #[Test]
    public function private_mode_is_unknown_not_false_when_the_evidence_is_missing_or_contradicted(): void
    {
        $this->assertNull(SmartSignals::privateMode(self::claims()), 'no storageProfile probe');
        $this->assertNull(SmartSignals::privateMode(self::claims(tier2: self::profile(['quotaStep' => null, 'heapStep' => null, 'opfs' => 'absent']))));
        $this->assertNull(SmartSignals::privateMode(self::claims(self::LINUX_FIREFOX, tier2: self::profile(['quotaStep' => 23, 'heapStep' => 24, 'opfs' => 'ok']), marks: self::V8)), 'a Firefox UA on a V8 engine is a contradiction for another rule, not evidence here');
        $this->assertNull(SmartSignals::privateMode(self::claims(self::LINUX_FIREFOX, tier2: self::profile(['quotaStep' => 27, 'heapStep' => null, 'opfs' => 'absent']), marks: self::SPIDERMONKEY)), 'Firefox with the file-system API off');
    }

    #[Test]
    public function private_mode_alone_never_scores_and_with_another_signal_adds_three(): void
    {
        $incognito = self::claims(tier2: self::profile(['quotaStep' => 23, 'heapStep' => 24, 'opfs' => 'ok']));
        $this->assertSame([], array_values(array_intersect(array_keys(self::fired($incognito)), ['private_mode_with_other_signals'])), 'a private tab alone is not fraud');
        $this->assertArrayNotHasKey('private_mode_with_other_signals', self::fired($incognito, new NetworkFacts(NetworkFacts::STATE_OK, 'NL', 1136)));
        $this->assertArrayHasKey('private_mode_with_other_signals', self::fired($incognito, new NetworkFacts(NetworkFacts::STATE_OK, 'NL', 14061, NetworkFacts::CATEGORY_HOSTING)));

        $vm = self::claims(tier2: self::profile(['quotaStep' => 23, 'heapStep' => 24, 'opfs' => 'ok']) + self::gpu('VirtualBox Graphics Adapter'));
        $this->assertArrayHasKey('private_mode_with_other_signals', self::fired($vm));
        $this->assertSame(3, EnvironmentConsistency::weights()['private_mode_with_other_signals']);
    }

    // ------------------------------------------------------------------ registry, features, details

    #[Test]
    public function every_new_rule_is_registered_described_soft_and_never_echoes_client_text(): void
    {
        $codes = ['ip_country_vs_locale', 'network_vpn', 'network_hosting', 'vm_gpu_renderer', 'vm_software_gpu_screen', 'emulator_android', 'private_mode_with_other_signals'];
        foreach ($codes as $code) {
            $this->assertTrue(CheckRegistry::isKnown($code), $code);
            $this->assertNotSame('', (string) CheckRegistry::descriptionOf($code));
            $this->assertLessThanOrEqual(8, EnvironmentConsistency::weights()[$code], 'no smart signal is worth more than 8');
            $this->assertSame(CheckRegistry::describe()[$code]['default_weight'], EnvironmentConsistency::weights()[$code], 'the registry and the rule table agree');
        }

        $marker = 'ZQX-CLIENT-STRING-7731';
        $claims = self::claims(self::WINDOWS_CHROME.' '.$marker, ['language' => 'nl-NL', 'languages' => ['nl-NL']], self::gpu('VMware '.$marker) + self::profile(['quotaStep' => 23, 'heapStep' => 24, 'opfs' => 'ok']));
        foreach (self::fired($claims, new NetworkFacts(NetworkFacts::STATE_OK, 'ES', 1, NetworkFacts::CATEGORY_HOSTING)) as $detail) {
            $this->assertStringNotContainsString($marker, $detail);
        }
    }

    #[Test]
    public function the_features_expose_the_facts_to_the_model_without_a_verdict(): void
    {
        $claims = self::claims(tier2: self::gpu('VMware SVGA 3D') + self::profile(['quotaStep' => 23, 'heapStep' => 24, 'opfs' => 'ok']), screen: ['width' => 1024, 'height' => 768]);
        $features = SmartSignals::features($claims, new NetworkFacts(NetworkFacts::STATE_OK, 'ES'));

        ksort($features);
        $this->assertSame(['sig_locale_disagreements' => 2.0, 'sig_private_mode' => 0.5, 'sig_vm_gpu' => 1.0, 'sig_vm_screen' => 1.0], $features);
        $this->assertSame([], SmartSignals::features(self::claims()), 'an honest desktop has none');
        foreach (array_keys($features) as $name) {
            $this->assertTrue(FeatureCatalogue::knows($name), $name);
        }
        $built = FeatureCatalogue::build([], 0, null, 0, 0, false, $features + (new NetworkFacts(NetworkFacts::STATE_OK, 'ES', 1, NetworkFacts::CATEGORY_VPN))->features() + ['vel_burst' => 1.0, 'made_up' => 1.0]);
        $this->assertArrayHasKey('net_vpn', $built);
        $this->assertArrayHasKey('vel_burst', $built);
        $this->assertSame(2.0, $built['sig_locale_disagreements']);
        $this->assertArrayNotHasKey('made_up', $built, 'only catalogue names enter the vector');
    }
}

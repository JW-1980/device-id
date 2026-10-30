<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\Keys\DeviceComponents;
use NutriCompare\Fingerprint\Keys\DeviceKeyDeriver;
use NutriCompare\Fingerprint\ProbeRegistry;
use NutriCompare\Fingerprint\Support\Config;
use NutriCompare\Fingerprint\Support\TransportIntegrityResult;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The soft components added with probe set 4 (`keyboard`, `gpuCaps`, `codecsHw`): what each
 * reads, when it is absent, that it never reaches a device key, and that the trust projection
 * drops it where the engine's own protection makes it a property of the protection.
 */
final class DeviceComponentsTest extends TestCase
{
    private const SECRET = 'device-components-test-secret-0123456789abcdef';

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
     * @return array<string, mixed>
     */
    private static function claims(): array
    {
        $claims = json_decode((string) file_get_contents(__DIR__.'/../Fixtures/fingerprint/claims-chromium.json'), true, 64, JSON_THROW_ON_ERROR);
        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, scalar|null>
     */
    private static function components(array $claims, ?string $secret = self::SECRET): array
    {
        return DeviceComponents::fromClaims($claims, new TransportIntegrityResult, $secret);
    }

    // ---------------------------------------------------------------- keyboard

    #[Test]
    public function the_keyboard_layout_is_a_keyed_class_that_separates_layouts(): void
    {
        $claims = self::claims();
        $claims['tier2']['keyboardLayout'] = ['hash' => 'aaaaaaaa', 'size' => 46];
        $qwerty = self::components($claims)['keyboard'];

        $claims['tier2']['keyboardLayout'] = ['hash' => 'bbbbbbbb', 'size' => 46];
        $azerty = self::components($claims)['keyboard'];

        $this->assertIsString($qwerty);
        $this->assertStringStartsWith('keyboard:', $qwerty);
        $this->assertNotSame($qwerty, $azerty);
        $this->assertStringNotContainsString('aaaaaaaa', $qwerty, 'the client hash is keyed, not stored');
        $this->assertNotSame($qwerty, self::components($claims, str_repeat('x', 40))['keyboard'], 'the class is bound to the deployment secret');
    }

    #[Test]
    public function an_empty_map_a_missing_secret_or_a_hostile_hash_is_absent_not_a_shared_constant(): void
    {
        $claims = self::claims();
        // The harness measured headless Chromium resolving an empty map; every headless machine
        // would otherwise "agree" on one layout.
        $claims['tier2']['keyboardLayout'] = ['hash' => 'cccccccc', 'size' => 0];
        $this->assertNull(self::components($claims)['keyboard']);

        $claims['tier2']['keyboardLayout'] = ['hash' => 'cccccccc', 'size' => 46];
        $this->assertNull(self::components($claims, null)['keyboard']);

        foreach (['not-hex!', 'CCCCCCCC', '', 12345678, ['x']] as $hash) {
            $claims['tier2']['keyboardLayout'] = ['hash' => $hash, 'size' => 46];
            $this->assertNull(self::components($claims)['keyboard'], json_encode($hash, JSON_THROW_ON_ERROR));
        }
    }

    #[Test]
    public function the_keyboard_is_enabled_by_default_and_never_expected_for_coverage(): void
    {
        $this->assertNotContains('keyboardLayout', ProbeRegistry::DEFAULT_DISABLED);
        $this->assertContains('keyboard', DeviceComponents::SOFT);
        foreach (['keyboard', 'gpuCaps', 'codecsHw'] as $bonus) {
            $this->assertNotContains($bonus, DeviceComponents::expectedFor('chromium'), $bonus.' exists in some browsers only');
        }
    }

    // ---------------------------------------------------------------- gpuCaps

    /**
     * @param  array<string, mixed>  $webgpu
     * @param  array<string, mixed>  $caps
     * @return array<string, mixed>
     */
    private static function withCaps(array $webgpu = [], array $caps = []): array
    {
        $claims = self::claims();
        $claims['tier2']['gpu']['webgpu'] = $webgpu === [] ? null : $webgpu + ['vendor' => 'nvidia', 'architecture' => 'ada'];
        $claims['tier2']['gpu']['webgl']['caps'] = $caps + ['compressed' => 's3tc,bptc', 'samples' => '8,4', 'maxSamples' => 8];

        return $claims;
    }

    #[Test]
    public function the_gpu_capability_class_changes_with_one_feature_and_is_engine_conditioned(): void
    {
        $base = self::components(self::withCaps(['features' => 'shader-f16,texture-compression-bc', 'limits' => '32,27,15,14', 'subgroups' => '32/32', 'canvasFormat' => 'bgra8unorm']))['gpuCaps'];
        $one = self::components(self::withCaps(['features' => 'shader-f16,texture-compression-bc,timestamp-query', 'limits' => '32,27,15,14', 'subgroups' => '32/32', 'canvasFormat' => 'bgra8unorm']))['gpuCaps'];
        $webglOnly = self::components(self::withCaps([], ['compressed' => 'astc,etc']))['gpuCaps'];

        $this->assertIsString($base);
        $this->assertStringStartsWith('caps:chromium:', $base);
        $this->assertNotSame($base, $one, 'a changed WebGPU feature changes the class (so the matcher test can flip)');
        $this->assertNotSame($base, $webglOnly);

        // The same capabilities under another engine are another, incomparable class.
        $firefox = self::withCaps(['features' => 'shader-f16,texture-compression-bc', 'limits' => '32,27,15,14', 'subgroups' => '32/32', 'canvasFormat' => 'bgra8unorm']);
        $firefox['tier1']['environment']['identity']['userAgent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';
        $this->assertStringStartsWith('caps:gecko:', (string) self::components($firefox)['gpuCaps']);
    }

    #[Test]
    public function the_gpu_capability_class_is_absent_without_data_or_with_hostile_data(): void
    {
        $none = self::claims();
        unset($none['tier2']['gpu']['webgl']['caps'], $none['tier2']['gpu']['webgpu']);
        $this->assertNull(self::components($none)['gpuCaps']);
        $this->assertNotNull(self::components(self::withCaps())['gpuCaps'], 'precondition: the helper claim set yields a class');

        foreach (['<script>', str_repeat('a', 700)] as $hostile) {
            $this->assertNull(self::components(self::withCaps([], ['compressed' => $hostile]))['gpuCaps'], substr($hostile, 0, 12));
        }
        $this->assertNull(self::components(self::withCaps(), null)['gpuCaps'], 'keyed: no secret, no class');
    }

    // ---------------------------------------------------------------- codecsHw

    /**
     * @return array<string, mixed>
     */
    private static function withCodecs(string $hevc10 = '111', string $encH264 = '11'): array
    {
        $claims = self::claims();
        $claims['tier2']['decoders'] = [
            'h264' => '111', 'vp9' => '110', 'av1' => '100', 'hevc' => '110', 'hevc10' => $hevc10, 'av1_10' => '100', 'vp9_2' => '110', 'h264_4k' => '111',
            'enc' => ['h264' => $encH264, 'vp9' => '10', 'av1' => '10'], 'rtc' => 'AV1,H264,VP8',
        ];

        return $claims;
    }

    #[Test]
    public function the_hardware_codec_class_keeps_only_the_power_efficient_bits(): void
    {
        $this->assertSame('hw:10001001|enc:000', self::components(self::withCodecs('101', '10'))['codecsHw']);

        // `supported` and `smooth` move with the browser build: they do not change the class.
        $a = self::withCodecs('101');
        $b = self::withCodecs('111');
        $this->assertSame(self::components($a)['codecsHw'], self::components($b)['codecsHw']);

        // A hardware bit does.
        $this->assertNotSame(self::components(self::withCodecs('100'))['codecsHw'], self::components(self::withCodecs('101'))['codecsHw']);
        $this->assertNotSame(self::components(self::withCodecs('101', '10'))['codecsHw'], self::components(self::withCodecs('101', '11'))['codecsHw']);
    }

    #[Test]
    public function the_hardware_codec_class_is_unknown_when_any_query_failed_or_the_client_is_older(): void
    {
        $this->assertNull(self::components(self::withCodecs('err'))['codecsHw']);
        $this->assertNull(self::components(self::withCodecs('111', 'err'))['codecsHw']);

        $old = self::claims();
        $old['tier2']['decoders'] = ['h264' => '111', 'vp9' => '110', 'av1' => '100'];
        $this->assertNull(self::components($old)['codecsHw']);
        $this->assertNotNull(self::components($old)['decoders'], 'the original decoders component is untouched');
    }

    // ---------------------------------------------------------------- keys and trust

    #[Test]
    public function none_of_the_new_components_or_their_claims_reaches_a_device_key(): void
    {
        Config::use(['fingerprint' => ['device_key_secret' => self::SECRET]]);
        $deriver = new DeviceKeyDeriver;

        $bare = self::claims();
        $rich = self::withCaps(['features' => 'shader-f16'], ['compressed' => 'astc']);
        $rich['tier2']['decoders'] = self::withCodecs()['tier2']['decoders'];
        $rich['tier2']['keyboardLayout'] = ['hash' => 'abcdef01', 'size' => 46];
        $rich['integrity']['data']['canvasPattern'] = ['state' => 'ok', 'value' => ['exact' => true, 'deviations' => 0, 'stable' => true]];
        $rich['integrity']['data']['automationMarks'] = ['state' => 'ok', 'value' => ['globals' => 0, 'cdc' => false, 'pw' => false, 'outerEqualsInner' => false, 'historyLength' => 4]];

        $before = $deriver->keys($bare, new TransportIntegrityResult);
        $after = $deriver->keys($rich, new TransportIntegrityResult);
        $this->assertNotNull($before);
        $this->assertNotNull($after);
        $this->assertNotNull($before->browserKey);
        $this->assertSame($before->browserKey, $after->browserKey);
        $this->assertSame($before->hardwareKey, $after->hardwareKey);
        $this->assertSame(['os', 'arch', 'touch'], DeviceComponents::HARD);
        $this->assertNotNull($after->components['keyboard']);
        $this->assertNotNull($after->components['gpuCaps']);
        $this->assertNotNull($after->components['codecsHw']);
    }

    #[Test]
    public function brave_and_rfp_drop_the_capability_components_and_stock_chromium_keeps_them(): void
    {
        $claims = self::withCaps(['features' => 'shader-f16'], []);
        $claims['tier2']['keyboardLayout'] = ['hash' => 'abcdef01', 'size' => 46];
        $claims['tier2']['decoders'] = self::withCodecs()['tier2']['decoders'];
        $stock = self::components($claims);
        $this->assertNotNull($stock['keyboard']);
        $this->assertNotNull($stock['gpuCaps']);
        $this->assertNotNull($stock['codecsHw']);

        $claims['integrity']['data']['resistance'] = ['state' => 'ok', 'value' => ['brave' => true, 'rfp' => false, 'tor' => false, 'gecko' => false]];
        $claims['tier1']['engineIdentity'] = ['engine' => 'v8', 'errorOwnProps' => 'message,stack', 'stackShape' => 'at', 'internalError' => false];
        $claims['tier1']['environment']['identity']['userAgent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
        $brave = self::components($claims);
        $this->assertNull($brave['keyboard']);
        $this->assertNull($brave['gpuCaps']);
        $this->assertNotNull($brave['codecsHw'], 'Brave does not farble MediaCapabilities');

        $this->assertContains('gpuCaps', DeviceComponents::PROTECTED_UNTRUSTED);
        $this->assertContains('codecsHw', DeviceComponents::PROTECTED_UNTRUSTED);
    }
}

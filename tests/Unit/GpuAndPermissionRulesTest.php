<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\CheckRegistry;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;
use DeviceId\Support\TransportIntegrityResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The WebGL rules (`renderer_vs_limits`, `ch_platform_vs_gpu`) and the notification-permission
 * pair, on the claim shape the collector sends: `tier2.gpu.webgl.{renderer, limits, webgl2}`.
 *
 * The two WebGL rules are on by default (they used to ship at weight 0 as opt-in). They only
 * fire on combinations that cannot exist, and the weights are below every rule that a
 * JavaScript-only spoofer cannot defeat; no single check can block (see the weight invariant).
 */
final class GpuAndPermissionRulesTest extends TestCase
{
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

    public function test_the_webgl_rules_are_on_by_default_with_the_same_weight_in_both_tables(): void
    {
        $this->assertSame(12, EnvironmentConsistency::weights()['renderer_vs_limits']);
        $this->assertSame(10, EnvironmentConsistency::weights()['ch_platform_vs_gpu']);
        $this->assertSame(12, CheckRegistry::describe()['renderer_vs_limits']['default_weight']);
        $this->assertSame(10, CheckRegistry::describe()['ch_platform_vs_gpu']['default_weight']);
    }

    public function test_the_two_rules_that_had_no_input_are_gone_from_both_tables(): void
    {
        foreach (['storage_quota_round', 'stack_depth_anomalous'] as $code) {
            $this->assertNotContains($code, CheckRegistry::codes());
            $this->assertArrayNotHasKey($code, EnvironmentConsistency::weights());
        }
    }

    public function test_every_rule_weight_agrees_between_the_registry_and_the_rules(): void
    {
        $rules = EnvironmentConsistency::weights();

        foreach (CheckRegistry::describe() as $code => $check) {
            if (array_key_exists($code, $rules)) {
                $this->assertSame($rules[$code], $check['default_weight'], "{$code} differs between CheckRegistry and EnvironmentConsistency");
            }
        }
    }

    public function test_no_single_check_can_block_a_device_alone(): void
    {
        $heaviest = max(array_column(CheckRegistry::describe(), 'default_weight'));

        // CheckRegistry documents 45 as the heaviest single contradiction (score 68, challenge).
        $this->assertLessThanOrEqual(45, $heaviest);
    }

    /**
     * @param  array<string, mixed>  $tier1
     * @param  array<string, mixed>  $tier2
     * @return list<string>
     */
    private static function codesForClaims(array $tier1, array $tier2): array
    {
        $contradictions = (new EnvironmentConsistency)->contradictions(['tier1' => $tier1, 'tier2' => $tier2], new TransportIntegrityResult);

        return array_map(static fn (array $contradiction): string => $contradiction['code'], $contradictions);
    }

    /**
     * @param  array<string, mixed>  $permissions
     * @return list<string>
     */
    private static function codesFor(array $permissions): array
    {
        $claims = [
            'tier2' => [
                'permissions' => [
                    'state' => 'ok',
                    'value' => $permissions,
                ],
            ],
        ];

        $contradictions = (new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult);

        return array_map(static fn (array $contradiction): string => $contradiction['code'], $contradictions);
    }

    public function test_the_headless_notification_permission_pair_fires(): void
    {
        $this->assertContains('notification_permission_vs_query', self::codesFor([
            'states' => 'notifications=prompt,camera=prompt',
            'notificationPermission' => 'denied',
        ]));
    }

    public function test_a_matching_notification_permission_pair_stays_silent(): void
    {
        $this->assertNotContains('notification_permission_vs_query', self::codesFor([
            'states' => 'notifications=prompt,camera=prompt',
            'notificationPermission' => 'prompt',
        ]));
    }

    private const WINDOWS_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    private const MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    private const LINUX_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    /**
     * @param  array<string, mixed>  $webgl  the `tier2.gpu.webgl` block
     * @return list<string>
     */
    private static function codesForGpu(
        array $webgl,
        string $platform = 'Windows',
        string $userAgent = self::WINDOWS_UA,
        bool $withHints = true,
    ): array {
        return self::codesForGpuNode(
            ['state' => 'ok', 'value' => ['webgpu' => null, 'webgl' => $webgl, 'mirroredParamsAgree' => true]],
            $platform,
            $userAgent,
            $withHints,
        );
    }

    /**
     * @param  array<string, mixed>  $node
     * @return list<string>
     */
    private static function codesForGpuNode(
        array $node,
        string $platform = 'Windows',
        string $userAgent = self::WINDOWS_UA,
        bool $withHints = true,
    ): array {
        $tier1 = [
            'environment' => [
                'state' => 'ok',
                'value' => [
                    'identity' => [
                        'userAgent' => $userAgent,
                    ],
                ],
            ],
        ];

        if ($withHints) {
            $tier1['uaClientHints'] = [
                'state' => 'ok',
                'value' => ['platform' => $platform],
            ];
        }

        $claims = [
            'tier1' => $tier1,
            'tier2' => [
                'gpu' => $node,
            ],
        ];

        $contradictions = (new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult);

        return array_map(static fn (array $contradiction): string => $contradiction['code'], $contradictions);
    }

    public function test_webgl_limits_below_the_specification_minimum_fire(): void
    {
        $this->assertContains('renderer_vs_limits', self::codesForGpu([
            'webgl2' => true,
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
            'limits' => ['MAX_VERTEX_ATTRIBS' => 4],
        ]));
    }

    public function test_plausible_webgl_limits_stay_silent(): void
    {
        $this->assertNotContains('renderer_vs_limits', self::codesForGpu([
            'webgl2' => true,
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
            'limits' => [
                'MAX_VERTEX_ATTRIBS' => 16,
                'MAX_VERTEX_UNIFORM_VECTORS' => 256,
                'MAX_FRAGMENT_UNIFORM_VECTORS' => 256,
                'MAX_VARYING_VECTORS' => 16,
                'MAX_COMBINED_TEXTURE_IMAGE_UNITS' => 32,
                'MAX_TEXTURE_IMAGE_UNITS' => 16,
            ],
        ]));
    }

    public function test_an_apple_renderer_on_windows_fires_the_platform_rule(): void
    {
        $this->assertContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
        ]));
    }

    public function test_a_windows_renderer_on_windows_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
        ]));
    }

    public function test_webgl1_minimum_limits_stay_silent(): void
    {
        $this->assertNotContains('renderer_vs_limits', self::codesForGpu([
            'webgl2' => false,
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
            'limits' => [
                'MAX_VERTEX_ATTRIBS' => 8,
                'MAX_VERTEX_UNIFORM_VECTORS' => 128,
                'MAX_FRAGMENT_UNIFORM_VECTORS' => 16,
                'MAX_VARYING_VECTORS' => 8,
                'MAX_COMBINED_TEXTURE_IMAGE_UNITS' => 8,
                'MAX_TEXTURE_IMAGE_UNITS' => 8,
            ],
        ]));
    }

    public function test_webgl2_limits_below_the_webgl2_minimum_fire(): void
    {
        $this->assertContains('renderer_vs_limits', self::codesForGpu([
            'webgl2' => true,
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
            'limits' => ['MAX_VERTEX_UNIFORM_VECTORS' => 128],
        ]));
    }

    public function test_a_software_renderer_stays_silent_for_both_gpu_rules(): void
    {
        $codes = self::codesForGpu([
            'webgl2' => true,
            'renderer' => 'Google SwiftShader',
            'limits' => ['MAX_VERTEX_ATTRIBS' => 4],
        ]);

        $this->assertNotContains('renderer_vs_limits', $codes);
        $this->assertNotContains('ch_platform_vs_gpu', $codes);
    }

    public function test_an_unavailable_gpu_probe_stays_silent(): void
    {
        $codes = self::codesForGpuNode(['state' => 'unavailable', 'reason' => 'no-webgl']);

        $this->assertNotContains('renderer_vs_limits', $codes);
        $this->assertNotContains('ch_platform_vs_gpu', $codes);
    }

    public function test_a_masked_renderer_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'WebKit WebGL',
        ]));
    }

    public function test_direct3d_on_macos_fires_the_platform_rule(): void
    {
        $this->assertContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
        ], 'macOS', self::MAC_UA));
    }

    public function test_an_apple_renderer_on_macos_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
        ], 'macOS', self::MAC_UA));
    }

    public function test_windows_on_arm_adreno_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'Adreno (TM) 650',
        ]));
    }

    public function test_linux_mali_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'Mali-G78',
        ], 'Linux', self::LINUX_UA));
    }

    public function test_chromeos_mesa_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'Mesa Intel(R) UHD Graphics 620 (CFL GT2)',
        ], 'Chrome OS', self::LINUX_UA));
    }

    public function test_the_ua_is_used_when_client_hints_are_absent(): void
    {
        $this->assertContains('ch_platform_vs_gpu', self::codesForGpu([
            'renderer' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
        ], 'Windows', self::WINDOWS_UA, false));
    }

    private const ANDROID_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36';

    public function test_a_software_rasteriser_with_low_limits_is_judged_by_nothing(): void
    {
        $limits = ['MAX_VERTEX_ATTRIBS' => 4];

        $this->assertNotContains('renderer_vs_limits', self::codesForGpu([
            'renderer' => 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)',
            'webgl2' => true,
            'limits' => $limits,
        ]));
        // The same limits on a hardware renderer do fire, so the silence above is the software skip.
        $this->assertContains('renderer_vs_limits', self::codesForGpu([
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
            'webgl2' => true,
            'limits' => $limits,
        ]));
    }

    public function test_a_limit_the_collector_could_not_read_is_unknown_not_below_the_minimum(): void
    {
        $this->assertNotContains('renderer_vs_limits', self::codesForGpu([
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
            'webgl2' => true,
            'limits' => ['MAX_VERTEX_ATTRIBS' => -1, 'MAX_VARYING_VECTORS' => -1],
        ]));
    }

    public function test_the_former_flat_gpu_shape_is_not_read(): void
    {
        $flat = ['state' => 'ok', 'value' => ['software' => false, 'webgl2' => true, 'renderer' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)', 'limits' => ['MAX_VERTEX_ATTRIBS' => 4]]];
        $codes = self::codesForGpuNode($flat);

        $this->assertNotContains('renderer_vs_limits', $codes);
        $this->assertNotContains('ch_platform_vs_gpu', $codes);
    }

    /**
     * @return array<string, array{string, string, string, string, bool}>
     */
    public static function gpuFamilyAgainstOs(): array
    {
        $apple = 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)';
        $direct3d = 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
        $wsl = 'D3D12 (NVIDIA GeForce RTX 3060)';
        $mesa = 'Mesa Intel(R) UHD Graphics 620 (CFL GT2)';

        return [
            'apple gpu on windows' => [$apple, 'Windows', self::WINDOWS_UA, 'x', true],
            'apple gpu on android' => [$apple, 'Android', self::ANDROID_UA, 'x', true],
            'apple gpu on chromeos' => [$apple, 'Chrome OS', self::LINUX_UA, 'x', true],
            'apple gpu on linux is Asahi, real' => [$apple, 'Linux', self::LINUX_UA, 'x', false],
            'direct3d on linux' => [$direct3d, 'Linux', self::LINUX_UA, 'x', true],
            'direct3d on android' => [$direct3d, 'Android', self::ANDROID_UA, 'x', true],
            'direct3d-backed mesa on linux is WSL, real' => [$wsl, 'Linux', self::LINUX_UA, 'x', false],
            'direct3d-backed mesa on macos' => [$wsl, 'macOS', self::MAC_UA, 'x', true],
            'adreno on chromeos is a Chromebook, real' => ['Adreno (TM) 635', 'Chrome OS', self::LINUX_UA, 'x', false],
            'adreno on macos' => ['Adreno (TM) 635', 'macOS', self::MAC_UA, 'x', true],
            'mali on android' => ['Mali-G78', 'Android', self::ANDROID_UA, 'x', false],
            'mesa on windows' => [$mesa, 'Windows', self::WINDOWS_UA, 'x', true],
            'mesa on macos' => [$mesa, 'macOS', self::MAC_UA, 'x', true],
            'mesa on android is Android-x86, real' => [$mesa, 'Android', self::ANDROID_UA, 'x', false],
            'mesa on linux' => [$mesa, 'Linux', self::LINUX_UA, 'x', false],
            'direct3d on windows' => [$direct3d, 'Windows', self::WINDOWS_UA, 'x', false],
        ];
    }

    #[DataProvider('gpuFamilyAgainstOs')]
    public function test_the_gpu_family_against_os_table(string $renderer, string $platform, string $userAgent, string $unused, bool $fires): void
    {
        $codes = self::codesForGpu(['renderer' => $renderer], $platform, $userAgent);

        if ($fires) {
            $this->assertContains('ch_platform_vs_gpu', $codes);
        } else {
            $this->assertNotContains('ch_platform_vs_gpu', $codes);
        }
    }
}

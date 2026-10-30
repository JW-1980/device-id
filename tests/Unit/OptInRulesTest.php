<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\CheckRegistry;
use NutriCompare\Fingerprint\Rules\EnvironmentConsistency;
use NutriCompare\Fingerprint\Support\Config;
use NutriCompare\Fingerprint\Support\TransportIntegrityResult;
use PHPUnit\Framework\TestCase;

/**
 * The rules WelZoLekker added (and the notification pair both apps share), run the way a
 * host that opted in runs them, plus the proof that the opt-in rules are silent for a host
 * that did not.
 */
final class OptInRulesTest extends TestCase
{
    /** The weights WelZoLekker enables in its `config/fingerprint.php`. */
    private const OPT_IN_WEIGHTS = [
        'renderer_vs_limits' => 12,
        'ch_platform_vs_gpu' => 10,
        'storage_quota_round' => 10,
        'stack_depth_anomalous' => 6,
    ];

    protected function setUp(): void
    {
        parent::setUp();

        Config::use(['fingerprint' => ['constraint_weights' => self::OPT_IN_WEIGHTS]]);
    }

    protected function tearDown(): void
    {
        Config::reset();

        parent::tearDown();
    }

    public function test_opt_in_rules_are_silent_for_a_host_that_did_not_enable_them(): void
    {
        Config::reset();

        $claims = [
            'tier1' => [
                'stackDepth' => ['state' => 'ok', 'value' => ['bucketed' => 1, 'innerDepth' => 200]],
            ],
            'tier2' => [
                'gpu' => ['state' => 'ok', 'value' => [
                    'software' => false,
                    'webgl2' => true,
                    'renderer' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
                    'limits' => ['MAX_VERTEX_ATTRIBS' => 4],
                ]],
                'storageEstimate' => ['state' => 'ok', 'value' => ['quota' => 1073741824]],
            ],
        ];

        $codes = array_column((new EnvironmentConsistency)->contradictions($claims, new TransportIntegrityResult), 'code');

        foreach (array_keys(self::OPT_IN_WEIGHTS) as $code) {
            $this->assertNotContains($code, $codes);
            $this->assertSame(0, EnvironmentConsistency::weights()[$code]);
            $this->assertContains($code, CheckRegistry::codes());
        }
    }

    public function test_an_enabled_opt_in_rule_carries_the_host_weight(): void
    {
        $this->assertSame(12, EnvironmentConsistency::weights()['renderer_vs_limits']);
        $this->assertSame(6, EnvironmentConsistency::weights()['stack_depth_anomalous']);
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

    public function test_a_power_of_two_storage_quota_fires(): void
    {
        $this->assertContains('storage_quota_round', self::codesForClaims([], [
            'storageEstimate' => ['state' => 'ok', 'value' => ['quota' => 2147483648]],
        ]));
    }

    public function test_a_measured_storage_quota_stays_silent(): void
    {
        $this->assertNotContains('storage_quota_round', self::codesForClaims([], [
            'storageEstimate' => ['state' => 'ok', 'value' => ['quota' => 299977904946]],
        ]));
    }

    public function test_an_inner_stack_depth_far_above_its_bucket_fires(): void
    {
        $this->assertContains('stack_depth_anomalous', self::codesForClaims([
            'stackDepth' => ['state' => 'ok', 'value' => ['bucketed' => 10, 'innerDepth' => 53]],
        ], []));
    }

    public function test_an_inner_stack_depth_at_the_bound_stays_silent(): void
    {
        $this->assertNotContains('stack_depth_anomalous', self::codesForClaims([
            'stackDepth' => ['state' => 'ok', 'value' => ['bucketed' => 10, 'innerDepth' => 52]],
        ], []));
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
     * @param  array<string, mixed>  $gpu
     * @return list<string>
     */
    private static function codesForGpu(
        array $gpu,
        string $platform = 'Windows',
        string $userAgent = self::WINDOWS_UA,
        bool $withHints = true,
    ): array {
        return self::codesForGpuNode(
            ['state' => 'ok', 'value' => $gpu],
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
            'software' => false,
            'webgl2' => true,
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
            'limits' => ['MAX_VERTEX_ATTRIBS' => 4],
        ]));
    }

    public function test_plausible_webgl_limits_stay_silent(): void
    {
        $this->assertNotContains('renderer_vs_limits', self::codesForGpu([
            'software' => false,
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
            'software' => false,
            'renderer' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
        ]));
    }

    public function test_a_windows_renderer_on_windows_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'software' => false,
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
        ]));
    }

    public function test_webgl1_minimum_limits_stay_silent(): void
    {
        $this->assertNotContains('renderer_vs_limits', self::codesForGpu([
            'software' => false,
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
            'software' => false,
            'webgl2' => true,
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)',
            'limits' => ['MAX_VERTEX_UNIFORM_VECTORS' => 128],
        ]));
    }

    public function test_a_software_renderer_stays_silent_for_both_gpu_rules(): void
    {
        $codes = self::codesForGpu([
            'software' => true,
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
            'software' => false,
            'renderer' => 'WebKit WebGL',
        ]));
    }

    public function test_direct3d_on_macos_fires_the_platform_rule(): void
    {
        $this->assertContains('ch_platform_vs_gpu', self::codesForGpu([
            'software' => false,
            'renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
        ], 'macOS', self::MAC_UA));
    }

    public function test_an_apple_renderer_on_macos_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'software' => false,
            'renderer' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
        ], 'macOS', self::MAC_UA));
    }

    public function test_windows_on_arm_adreno_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'software' => false,
            'renderer' => 'Adreno (TM) 650',
        ]));
    }

    public function test_linux_mali_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'software' => false,
            'renderer' => 'Mali-G78',
        ], 'Linux', self::LINUX_UA));
    }

    public function test_chromeos_mesa_stays_silent(): void
    {
        $this->assertNotContains('ch_platform_vs_gpu', self::codesForGpu([
            'software' => false,
            'renderer' => 'Mesa Intel(R) UHD Graphics 620 (CFL GT2)',
        ], 'Chrome OS', self::LINUX_UA));
    }

    public function test_the_ua_is_used_when_client_hints_are_absent(): void
    {
        $this->assertContains('ch_platform_vs_gpu', self::codesForGpu([
            'software' => false,
            'renderer' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)',
        ], 'Windows', self::WINDOWS_UA, false));
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\Keys\DeviceComponents;
use DeviceId\Keys\DeviceKeyDeriver;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../tools/capture/CaptureAnalysis.php';

/**
 * One client-reported bit must not change the hardware identity (skeptical review M1).
 *
 * The trust projection (`DeviceComponents::untrusted()`) nulls components the evidence says are
 * noised or a protection's constants. Several of its inputs are single booleans in the client's
 * body (`canvasFill.exact`, `canvasPattern.exact`, `resistance.brave`), and `resistance.brave`
 * was honoured on ANY Chromium: one bit nulled fonts, emoji, gpu, gpuMath, voices and more, so
 * a host's per-hardware hash over those components changed with the bit. The hardware identity
 * ({@see DeviceKeyDeriver::hardwareIdentity()}) is computed from the measured components with no
 * client flag applied, and Brave is honoured only with Brave's own brand in the brands and the
 * Sec-CH-UA header.
 *
 * What no server can prevent, stated rather than hidden: a client that forges a MEASUREMENT (one
 * bit of `tier2.scripts.bits`) derives a different identity. The hardware identity is a
 * correlation feature, not proof; hosts must not use it as the only dedupe key.
 */
final class HardwareIdentityTest extends TestCase
{
    private const HONEST = __DIR__.'/../Fixtures/fingerprint/captures/linux-container.linux.chromium.headed.honest.json';

    protected function setUp(): void
    {
        parent::setUp();
        CaptureAnalysis::configure();
    }

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    /**
     * @return array<string, mixed>
     */
    private static function record(): array
    {
        /** @var array<string, mixed> $record */
        $record = json_decode((string) file_get_contents(self::HONEST), true, 64, JSON_THROW_ON_ERROR);

        return $record;
    }

    private static function identity(array $record): ?string
    {
        return (new DeviceKeyDeriver)->hardwareIdentity(CaptureAnalysis::mergedClaims($record), CaptureAnalysis::transport($record));
    }

    /**
     * @param  array<string, mixed>  $value
     * @return array<string, mixed>
     */
    private static function withIntegrityData(array $record, string $probe, array $value): array
    {
        // Both envelopes: the identify form merges integrity data with the deferred (tier-2) keys winning.
        foreach (['tier1', 'tier2'] as $slot) {
            if (is_array($record['claims'][$slot] ?? null)) {
                $record['claims'][$slot]['integrity']['data'][$probe] = ['state' => 'ok', 'value' => $value];
            }
        }

        return $record;
    }

    /** @return iterable<string, array{string, array<string, mixed>}> */
    public static function clientFlags(): iterable
    {
        yield 'Brave shields flag' => ['resistance', ['brave' => true, 'timerGranularityUs' => 100, 'rfp' => false, 'tor' => false, 'gecko' => false]];
        yield 'RFP flag on a Chromium' => ['resistance', ['brave' => false, 'timerGranularityUs' => 100, 'rfp' => true, 'tor' => false, 'gecko' => false]];
        yield 'canvas fill noised' => ['canvasFill', ['exact' => false, 'deviations' => 12]];
        yield 'canvas pattern noised' => ['canvasPattern', ['exact' => false, 'deviations' => 40, 'stable' => true]];
    }

    #[Test]
    #[DataProvider('clientFlags')]
    public function a_client_flag_alone_does_not_change_the_hardware_identity(string $probe, array $value): void
    {
        $honest = self::identity(self::record());
        $flagged = self::identity(self::withIntegrityData(self::record(), $probe, $value));

        $this->assertNotNull($honest);
        $this->assertSame($honest, $flagged);
    }

    #[Test]
    public function the_hardware_identity_is_keyed_over_the_measured_high_entropy_components(): void
    {
        $record = self::record();
        $claims = CaptureAnalysis::mergedClaims($record);
        $measured = DeviceComponents::fromClaims($claims, CaptureAnalysis::transport($record), CaptureAnalysis::KEY_SECRET, []);

        $this->assertSame(['fonts', 'gpu', 'gpuMath', 'voices', 'emoji', 'scripts'], DeviceComponents::HARDWARE_IDENTITY);
        $this->assertNotNull($measured['scripts']);

        // A forged measurement is a different identity: the stated limit of any client-side hash.
        $forged = $record;
        $bits = (string) $forged['claims']['tier2']['tier2']['scripts']['bits'];
        $forged['claims']['tier2']['tier2']['scripts']['bits'] = ($bits[0] === '1' ? '0' : '1').substr($bits, 1);
        $this->assertNotSame(self::identity($record), self::identity($forged));

        // Unkeyed when there is no secret.
        Config::use(['fingerprint' => ['device_key_secret' => null]]);
        $this->assertNull(self::identity($record));
    }

    #[Test]
    public function a_brave_flag_on_a_chromium_without_the_brave_brand_is_not_honoured(): void
    {
        $record = self::withIntegrityData(self::record(), 'resistance', ['brave' => true, 'rfp' => false, 'tor' => false, 'gecko' => false]);
        $claims = CaptureAnalysis::mergedClaims($record);
        $transport = CaptureAnalysis::transport($record);

        $this->assertFalse(EnvironmentConsistency::protectedBrave($claims, $transport));
        $this->assertSame([], DeviceComponents::untrusted($claims, $transport), 'a flag alone buys no untrusted components');
    }

    #[Test]
    public function brave_with_its_brand_in_the_brands_and_the_header_is_honoured_and_has_no_hardware_identity(): void
    {
        $record = self::withIntegrityData(self::record(), 'resistance', ['brave' => true, 'rfp' => false, 'tor' => false, 'gecko' => false]);
        $brands = [['brand' => 'Brave', 'version' => '153'], ['brand' => 'Chromium', 'version' => '153'], ['brand' => 'Not_A Brand', 'version' => '8']];
        $record['claims']['tier1']['tier1']['uaClientHints']['brands'] = $brands;
        $record['claims']['tier1']['tier1']['uaClientHints']['high']['brands'] = $brands;
        foreach ($record['transport']['claims_request_headers'] as $i => $pair) {
            if (strtolower($pair[0]) === 'sec-ch-ua') {
                $record['transport']['claims_request_headers'][$i][1] = '"Brave";v="153", "Chromium";v="153", "Not_A Brand";v="8"';
            }
        }
        $claims = CaptureAnalysis::mergedClaims($record);
        $transport = CaptureAnalysis::transport($record);

        $this->assertTrue(EnvironmentConsistency::protectedBrave($claims, $transport));
        $this->assertContains('fonts', DeviceComponents::untrusted($claims, $transport));
        $this->assertNull(self::identity($record), 'farbled values are per session: no hardware identity rather than a random one');

        // The brand in the page alone, with a header that lacks it, is not enough.
        foreach ($record['transport']['claims_request_headers'] as $i => $pair) {
            if (strtolower($pair[0]) === 'sec-ch-ua') {
                $record['transport']['claims_request_headers'][$i][1] = '"Chromium";v="153", "Not_A Brand";v="8"';
            }
        }
        $this->assertFalse(EnvironmentConsistency::protectedBrave(CaptureAnalysis::mergedClaims($record), CaptureAnalysis::transport($record)));
    }

    #[Test]
    public function the_device_keys_carry_the_hardware_identity(): void
    {
        $record = self::record();
        $keys = (new DeviceKeyDeriver)->keys(CaptureAnalysis::mergedClaims($record), CaptureAnalysis::transport($record));

        $this->assertNotNull($keys);
        $this->assertSame(self::identity($record), $keys->hardwareIdentity);
    }
}

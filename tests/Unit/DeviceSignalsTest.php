<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Support\DeviceSignals;
use PHPUnit\Framework\TestCase;

class DeviceSignalsTest extends TestCase
{
    public function test_only_the_keys_the_risk_rules_read_are_kept(): void
    {
        $signals = DeviceSignals::sanitize([
            'userAgent' => ['platform' => 'MacIntel', 'maxTouchPoints' => 0, 'userAgent' => 'Mozilla/5.0 full string'],
            'webgl' => ['vendor' => 'Apple Inc.', 'renderer' => 'Apple M2', 'extensions' => ['a', 'b']],
            'screen' => ['width' => 1512, 'height' => 982, 'colorDepth' => 30],
            'timezone' => ['timezone' => 'Europe/Amsterdam'],
            'email' => 'someone@example.com',
            'history' => array_fill(0, 100, 'https://example.com/page'),
        ]);

        $this->assertSame([
            'userAgent' => ['platform' => 'MacIntel', 'maxTouchPoints' => 0],
            'webgl' => ['vendor' => 'Apple Inc.', 'renderer' => 'Apple M2'],
            'screen' => ['width' => 1512, 'height' => 982],
            'timezone' => ['timezone' => 'Europe/Amsterdam'],
        ], $signals);
    }

    /**
     * Out-of-bounds values are brought inside the bounds the way the rules
     * read them, not thrown away: dropping them changed verdicts (5000 touch
     * points stopped being a touch mismatch, a 12.5 px screen became
     * headless). DeviceSignalsVerdictTest checks the verdicts themselves.
     */
    public function test_values_out_of_bounds_are_bounded_and_values_of_no_use_are_dropped(): void
    {
        $signals = DeviceSignals::sanitize([
            'userAgent' => ['platform' => str_repeat('x', 65), 'maxTouchPoints' => 1001],
            'webgl' => ['vendor' => ['nested'], 'renderer' => str_repeat('r', 256)],
            'screen' => ['width' => -1, 'height' => 12.5],
            'timezone' => ['timezone' => 42],
        ]);

        $this->assertSame([
            'userAgent' => ['platform' => str_repeat('x', 64), 'maxTouchPoints' => 1000],
            'webgl' => ['renderer' => str_repeat('r', 255)],
            'screen' => ['width' => 0, 'height' => 12],
            // Not text: the rules call that an anomaly, and so does a blank.
            'timezone' => ['timezone' => ''],
        ], $signals);
    }

    public function test_a_flat_null_is_not_stored_as_a_value(): void
    {
        $this->assertSame([], DeviceSignals::sanitize(['timezone' => null, 'platform' => null, 'maxTouchPoints' => null]));
    }

    public function test_text_that_is_not_utf8_is_repaired_rather_than_breaking_the_row(): void
    {
        $signals = DeviceSignals::sanitize(['webgl' => ['renderer' => "\xff\xfeHeadless"]]);

        $renderer = $signals['webgl']['renderer'] ?? null;
        $this->assertIsString($renderer);
        $this->assertTrue(mb_check_encoding($renderer, 'UTF-8'));
        $this->assertStringEndsWith('Headless', $renderer);
        $this->assertNotFalse(json_encode($signals));
    }

    public function test_digit_strings_count_as_integers_and_null_strings_are_kept(): void
    {
        $this->assertSame(
            ['userAgent' => ['platform' => null, 'maxTouchPoints' => 5], 'screen' => ['width' => 800, 'height' => 600]],
            DeviceSignals::sanitize(['userAgent' => ['platform' => null, 'maxTouchPoints' => '5'], 'screen' => ['width' => '800', 'height' => '600']]),
        );
    }

    public function test_the_flat_legacy_keys_are_stored_in_the_nested_shape(): void
    {
        $this->assertSame(
            ['userAgent' => ['platform' => 'Win32', 'maxTouchPoints' => 20], 'timezone' => ['timezone' => '']],
            DeviceSignals::sanitize(['platform' => 'Win32', 'maxTouchPoints' => 20, 'timezone' => '', 'junk' => 'x']),
        );
    }

    public function test_nothing_usable_is_an_empty_array(): void
    {
        $this->assertSame([], DeviceSignals::sanitize(['foo' => 'bar', 'userAgent' => 'not an object']));
    }
}

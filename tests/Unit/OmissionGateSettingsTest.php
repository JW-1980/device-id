<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\Scoring\OmissionGateSettings;
use NutriCompare\Fingerprint\Support\Config;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * `OmissionGateSettings` — the omission gate's settings normaliser, moved from the
 * application's settings store into the package on 2026-10-21. Fixed values from the store's
 * normalisation as it was before the move (FingerprintSettingsStore::omissionGate() at
 * c845a583: enabled default true, min_reported clamped to 1..100 with default 85, purposes
 * filtered to the configured collection purposes, de-duplicated).
 */
final class OmissionGateSettingsTest extends TestCase
{
    private const KNOWN = ['signin', 'register', 'password_reset'];

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    #[Test]
    public function an_empty_block_yields_the_defaults(): void
    {
        self::assertSame(
            ['enabled' => true, 'min_reported' => 85, 'purposes' => []],
            OmissionGateSettings::fromConfig([], self::KNOWN),
        );
    }

    #[Test]
    public function values_are_clamped_and_wrong_types_fall_back(): void
    {
        self::assertSame(1, OmissionGateSettings::fromConfig(['min_reported' => 0], self::KNOWN)['min_reported']);
        self::assertSame(100, OmissionGateSettings::fromConfig(['min_reported' => 150], self::KNOWN)['min_reported']);
        self::assertSame(70, OmissionGateSettings::fromConfig(['min_reported' => '70'], self::KNOWN)['min_reported']);
        self::assertSame(85, OmissionGateSettings::fromConfig(['min_reported' => 'abc'], self::KNOWN)['min_reported']);
        self::assertFalse(OmissionGateSettings::fromConfig(['enabled' => false], self::KNOWN)['enabled']);
        self::assertTrue(OmissionGateSettings::fromConfig(['enabled' => 'false'], self::KNOWN)['enabled'], 'a wrong-typed switch falls back, it is not coerced');
    }

    #[Test]
    public function purposes_are_filtered_to_the_known_ones_and_deduplicated(): void
    {
        $settings = OmissionGateSettings::fromConfig(
            ['purposes' => ['register', 'regsiter', 'register', 'password_reset', 3, '']],
            [...self::KNOWN, '', 7],
        );

        self::assertSame(['register', 'password_reset'], $settings['purposes']);
        self::assertSame([], OmissionGateSettings::fromConfig(['purposes' => 'register'], self::KNOWN)['purposes']);
    }

    #[Test]
    public function normalising_a_normalised_block_changes_nothing(): void
    {
        $once = OmissionGateSettings::fromConfig(['enabled' => false, 'min_reported' => 90, 'purposes' => ['register', 'signin']], self::KNOWN);

        self::assertSame($once, OmissionGateSettings::fromConfig($once, self::KNOWN));
    }

    #[Test]
    public function current_reads_the_gate_and_the_purposes_through_config(): void
    {
        Config::use(['fingerprint' => [
            'omission_gate' => ['enabled' => true, 'min_reported' => 60, 'purposes' => ['register', 'checkout']],
            'purposes' => self::KNOWN,
        ]]);

        self::assertSame(
            ['enabled' => true, 'min_reported' => 60, 'purposes' => ['register']],
            OmissionGateSettings::current(),
        );
    }
}

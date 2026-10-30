<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\Matching\MatcherSettings;
use NutriCompare\Fingerprint\Support\Config;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * `MatcherSettings` — the matcher's settings normaliser, moved from the application's settings
 * store into the package on 2026-10-21 so a plain-PHP host and the application agree on every
 * default and clamp. Fixed values, written from the store's normalisation as it was before the
 * move (FingerprintSettingsStore::matcher() at c845a583); the application-side equality is
 * asserted in tests/Feature/Security/FingerprintSettingsStoreNormalisationTest.php.
 */
final class MatcherSettingsTest extends TestCase
{
    private const DEFAULTS = [
        'weights' => [],
        'link_posterior' => 0.8,
        'possible_posterior' => 0.5,
        'midpoint' => 3.0,
        'scale' => 1.5,
        'link_requires_high_entropy_agreement' => true,
        'high_entropy_components' => ['fonts', 'gpu', 'voices'],
        'veto_components' => ['fonts', 'gpu', 'panel'],
        'max_cluster_members' => 8,
        'window_days' => 90,
        'max_candidates' => 200,
        'fonts_agree_jaccard' => 0.8,
        'fonts_disagree_jaccard' => 0.3,
    ];

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    #[Test]
    public function an_empty_block_yields_the_shipped_defaults(): void
    {
        self::assertSame(self::DEFAULTS, MatcherSettings::fromConfig([]));
    }

    #[Test]
    public function weights_are_clamped_and_only_string_codes_with_numeric_weights_survive(): void
    {
        $settings = MatcherSettings::fromConfig(['weights' => [
            'fonts' => 99,      // above MAX_WEIGHT (60)
            'gpu' => -3,        // below 0
            'voices' => '2',    // numeric string
            'panel' => 'abc',   // not numeric: dropped
            7 => 1,             // not a string code: dropped
        ]]);

        self::assertSame(['fonts' => 60, 'gpu' => 0, 'voices' => 2], $settings['weights']);
    }

    #[Test]
    public function stored_overrides_apply_only_to_components_the_table_knows(): void
    {
        $settings = MatcherSettings::fromConfig(
            ['weights' => ['fonts' => 3, 'gpu' => 3]],
            ['fonts' => 10, 'gpu' => 100, 'invented' => 5, 'panel' => 1],
        );

        self::assertSame(['fonts' => 10, 'gpu' => 60], $settings['weights']);
        self::assertSame(['fonts' => 3], MatcherSettings::fromConfig(['weights' => ['fonts' => 3]], 'not-an-array')['weights']);
    }

    #[Test]
    public function thresholds_are_clamped_and_the_link_posterior_is_never_below_possible(): void
    {
        $settings = MatcherSettings::fromConfig([
            'possible_posterior' => 0.6,
            'link_posterior' => 0.3,
            'midpoint' => 500,
            'scale' => 0,
            'max_cluster_members' => 0,
            'window_days' => 99999,
            'max_candidates' => '50',
            'fonts_agree_jaccard' => 2,
            'fonts_disagree_jaccard' => 'x',
            'link_requires_high_entropy_agreement' => 'no',
            'high_entropy_components' => ['fonts', 'invented', 3, 'gpu'],
            'veto_components' => 'fonts',
        ]);

        self::assertSame(0.6, $settings['possible_posterior']);
        self::assertSame(0.6, $settings['link_posterior']);
        self::assertSame(100.0, $settings['midpoint']);
        self::assertSame(0.01, $settings['scale']);
        self::assertSame(1, $settings['max_cluster_members']);
        self::assertSame(3650, $settings['window_days']);
        self::assertSame(50, $settings['max_candidates']);
        self::assertSame(1.0, $settings['fonts_agree_jaccard']);
        self::assertSame(0.3, $settings['fonts_disagree_jaccard']);
        // Only an explicit false switches the high-entropy rule off.
        self::assertTrue($settings['link_requires_high_entropy_agreement']);
        self::assertFalse(MatcherSettings::fromConfig(['link_requires_high_entropy_agreement' => false])['link_requires_high_entropy_agreement']);
        self::assertSame(['fonts', 'gpu'], $settings['high_entropy_components']);
        self::assertSame(['fonts', 'gpu', 'panel'], $settings['veto_components'], 'a non-list falls back to the default');
    }

    #[Test]
    public function normalising_a_normalised_block_changes_nothing(): void
    {
        $once = MatcherSettings::fromConfig([
            'weights' => ['fonts' => 3, 'gpu' => 70, 'voices' => 2],
            'possible_posterior' => 0.55,
            'link_posterior' => 0.9,
            'scale' => 2,
            'high_entropy_components' => ['fonts'],
        ], ['fonts' => 5]);

        self::assertSame($once, MatcherSettings::fromConfig($once));
        self::assertSame(self::DEFAULTS, MatcherSettings::fromConfig(self::DEFAULTS));
    }

    #[Test]
    public function current_reads_the_matcher_block_through_config(): void
    {
        Config::use(['fingerprint' => ['matcher' => ['weights' => ['fonts' => 4], 'window_days' => 30]]]);

        $settings = MatcherSettings::current();

        self::assertSame(['fonts' => 4], $settings['weights']);
        self::assertSame(30, $settings['window_days']);
        self::assertSame(0.8, $settings['link_posterior']);
    }
}

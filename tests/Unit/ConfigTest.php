<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\Support\Config;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The package's configuration bridge (`NutriCompare\Fingerprint\Support\Config`): the static
 * `use()` snapshot a plain-PHP host passes, and the `resolveWith()` resolver the Laravel host
 * registers (App\Providers\FingerprintServiceProvider) so weights and bands edited on the admin
 * screen are read live rather than frozen at boot.
 *
 * A plain PHPUnit case on purpose: the bridge must work with no framework. Every test resets
 * the holder before and after, so no order dependence leaks into the next test (a Laravel test
 * that follows boots a fresh application, whose provider registers its resolver again).
 */
final class ConfigTest extends TestCase
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

    #[Test]
    public function the_snapshot_is_read_by_dotted_key_and_an_absent_key_returns_the_default(): void
    {
        Config::use(['fingerprint' => ['score_divisor' => 40, 'bands' => ['block' => 80]]]);

        self::assertTrue(Config::isSet());
        self::assertSame(40, Config::raw('fingerprint.score_divisor'));
        self::assertSame(80, Config::int('fingerprint.bands.block', 0));
        self::assertSame('fallback', Config::raw('fingerprint.missing', 'fallback'));
        self::assertNull(Config::raw('nothing.here'));
    }

    #[Test]
    public function the_resolver_wins_over_the_snapshot(): void
    {
        Config::use(['fingerprint' => ['score_divisor' => 40]]);
        Config::resolveWith(static fn (string $key, mixed $default): mixed => $key === 'fingerprint.score_divisor' ? 99 : $default);

        self::assertSame(99, Config::int('fingerprint.score_divisor', 40));
        // A key the resolver does not answer gets the caller's default — the snapshot is NOT
        // consulted behind the resolver's back.
        self::assertSame('d', Config::raw('fingerprint.bands', 'd'));
        self::assertSame([], Config::array('fingerprint.bands'));
    }

    #[Test]
    public function the_resolver_receives_the_key_and_the_callers_default_on_every_read(): void
    {
        $seen = [];
        Config::resolveWith(static function (string $key, mixed $default) use (&$seen): mixed {
            $seen[] = [$key, $default];

            return $default;
        });

        Config::raw('transport_integrity.fastcgi_header_order', true);
        Config::int('fingerprint.score_divisor', 40);
        Config::raw('fingerprint.bands');

        // Typed readers ask with a null default and apply their own afterwards; one read, one call.
        self::assertSame([
            ['transport_integrity.fastcgi_header_order', true],
            ['fingerprint.score_divisor', null],
            ['fingerprint.bands', null],
        ], $seen);
    }

    #[Test]
    public function reset_clears_the_resolver_and_the_snapshot(): void
    {
        Config::use(['fingerprint' => ['score_divisor' => 40]]);
        Config::resolveWith(static fn (string $key, mixed $default): mixed => 99);

        Config::reset();

        self::assertFalse(Config::isSet());
        self::assertSame(7, Config::int('fingerprint.score_divisor', 7));
        self::assertSame('d', Config::raw('fingerprint.score_divisor', 'd'));
    }

    #[Test]
    public function typed_readers_fall_back_on_wrong_types_rather_than_coercing(): void
    {
        Config::resolveWith(static fn (string $key, mixed $default): mixed => match ($key) {
            'int' => 'sixty',
            'numeric' => '60',
            'bool' => 'false',
            'float' => ['x'],
            'array' => 'not-an-array',
            default => $default,
        });

        self::assertSame(40, Config::int('int', 40));
        self::assertSame(60, Config::int('numeric', 40));
        self::assertTrue(Config::bool('bool', true), 'the string "false" is a wrong-typed value, not false');
        self::assertSame(1.5, Config::float('float', 1.5));
        self::assertSame([], Config::array('array'));
    }
}

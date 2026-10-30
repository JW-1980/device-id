<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Support;

use NutriCompare\Fingerprint\Settings;

/**
 * The bridge between the ported engine and whatever the host calls configuration.
 *
 * ## Why a static holder rather than constructor injection
 *
 * The engine was written as a set of static classes (`EnvironmentConsistency::evaluate()`,
 * `VerdictScorer::score()`, `RawHeaderCapture::parse()`) because that is what the Laravel
 * application had, and the whole point of this package is to be usable from a host with no
 * container at all. Converting eighteen classes to instance methods to satisfy a DI container
 * the package explicitly does not require would be a large, behaviour-neutral refactor with
 * a real chance of changing a rule — and a rule that changes silently is the one failure
 * mode this system cannot have.
 *
 * So the coupling is inverted: the host hands the values in once, and the engine reads them
 * through named accessors. `Config::use()` is the only entry point, and `Config::reset()`
 * exists so a test or a long-running worker can put it back.
 *
 * ## This is a HOLDER, not a service locator
 *
 * One static value, set once, read many. It is not resolved by key from an unbounded
 * namespace, and nothing in the engine reaches for anything that was not put in it: an
 * absent key returns the caller's default, which is how every threshold in this system has
 * always behaved. The alternative reading — "a global config" — is a fair criticism, and
 * the reason the next paragraph exists.
 *
 * ## Why values that are absent are not silently defaulted into existence
 *
 * `Settings` is strict about types. `Config::int('score_divisor', 40)` on a value of
 * `"sixty"` returns 40, not 0, because 0 would make every score a divisor and divide by it.
 * A wrong-typed value falling back to the caller's default is the correct behaviour for a
 * security threshold, and coercing it would turn a configuration typo into a silent
 * misconfiguration — which is the failure this whole package is about detecting elsewhere.
 *
 * ## Two ways in: a snapshot (`use()`) or a resolver (`resolveWith()`)
 *
 * A plain-PHP host has its configuration in an array and hands it over once with `use()`.
 *
 * A host whose values can change while the process runs must not do that. The Laravel
 * application is the case in point (2026-10-21, one-engine migration): its weights, bands,
 * matcher weights, omission gate and disabled probes live in the `settings` table and an
 * operator edits them on the admin screen. A snapshot taken when the process boots would be
 * stale for the rest of that process — inside one test, in a queue worker, under Octane —
 * and the engine would score with weights the operator has already changed. So such a host
 * registers a RESOLVER instead: `resolveWith(fn (string $key, mixed $default): mixed => …)`,
 * consulted on every read, and the host answers each key from its own live source.
 *
 * When a resolver is set it wins and the `use()` values are not consulted; `reset()` clears
 * both. Reads go through the resolver exactly once per `raw()` call, so the number of reads
 * the engine makes against the host's store is the number of `Config::` calls it makes —
 * this class adds no caching and no extra reads.
 */
final class Config
{
    /** @var array<string, mixed>|null */
    private static ?array $values = null;

    /** @var (callable(string, mixed): mixed)|null */
    private static $resolver = null;

    /**
     * Hand the engine its configuration.
     *
     * @param  array<string, mixed>  $values  Dotted keys are NOT flattened here; the
     *                                        traversal happens on read, so a caller can pass
     *                                        the same nested shape Laravel's `config()`
     *                                        returns and the two agree key for key.
     */
    public static function use(array $values): void
    {
        self::$values = $values;
    }

    /**
     * Build the holder straight from a `Settings` instance, flattening its overrides.
     *
     * The convenience path for a host that already has one: `Config::use(Settings::all())`.
     * Kept as a method rather than a union type on `use()` because `Settings::all()` returns
     * a flat map with `check_weights` already nested, and mixing that with a nested array is
     * exactly the inconsistency `read()` below would then have to guess at.
     */
    public static function useSettings(Settings $settings): void
    {
        self::$values = $settings->all();
    }

    /**
     * Forget everything.
     *
     * Required, not optional. A test that sets values and does not clear them makes the next
     * test depend on the order the two ran in, which is the class of failure that passes
     * locally and fails in CI.
     */
    public static function reset(): void
    {
        self::$values = null;
        self::$resolver = null;
    }

    /**
     * Answer every read from the host's own source, live.
     *
     * `$resolver($key, $default)` receives the dotted key the engine asked for (for example
     * `fingerprint.bands`) and the caller's default, and returns the value — or the default
     * when the host has none. The typed readers below then narrow it exactly as they narrow a
     * `use()` value, so a wrong-typed answer falls back rather than coercing.
     *
     * @param  callable(string, mixed): mixed  $resolver
     */
    public static function resolveWith(callable $resolver): void
    {
        self::$resolver = $resolver;
    }

    public static function isSet(): bool
    {
        return self::$resolver !== null || self::$values !== null;
    }

    public static function raw(string $key, mixed $default = null): mixed
    {
        if (self::$resolver !== null) {
            return (self::$resolver)($key, $default);
        }

        if (self::$values === null) {
            return $default;
        }

        $node = self::$values;
        foreach (explode('.', $key) as $part) {
            if (! is_array($node) || ! array_key_exists($part, $node)) {
                return $default;
            }
            $node = $node[$part];
        }

        return $node;
    }

    public static function int(string $key, int $default): int
    {
        $value = self::raw($key);

        return is_numeric($value) ? (int) $value : $default;
    }

    public static function float(string $key, float $default): float
    {
        $value = self::raw($key);

        return is_numeric($value) ? (float) $value : $default;
    }

    /**
     * Strictly a bool.
     *
     * The string `"false"` is NOT false. It is a wrong-typed value, and it falls back to the
     * default rather than being guessed at — coercing it would mean a typo could silently
     * enable a feature an operator meant to disable.
     */
    public static function bool(string $key, bool $default): bool
    {
        $value = self::raw($key);

        return is_bool($value) ? $value : $default;
    }

    /**
     * @return array<array-key, mixed>
     */
    public static function array(string $key): array
    {
        $value = self::raw($key);

        return is_array($value) ? $value : [];
    }
}

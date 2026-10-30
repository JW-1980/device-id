<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint;

/**
 * Typed reads of a settings array, with no framework underneath.
 *
 * ## Why this is an object rather than `config()` calls at each call site
 *
 * The Laravel package reads `config()`, which returns `mixed`, so a direct cast is an
 * unchecked conversion: a value arriving as a string, an array or null becomes a silently
 * wrong number, and a mistyped threshold becomes a wrong decision nobody can trace.
 *
 * The same reasoning applies here with nothing to do with a framework. A threshold that
 * arrives as `"sixty"` should be the configured 60, not 0 — because 0 would make every
 * request match it. So the narrowing happens once, in named readers, and a wrong-typed value
 * falls back to the caller's default rather than coercing.
 *
 * ## Every setting is a DEFAULT here, not a value
 *
 * The class is constructed with defaults only. A host supplies overrides, so an absent key
 * can never mean "0" or "false" by accident. That matters for the master switch in
 * particular: `enabled` defaults to **false**, and the feature is off unless a host turns it
 * on. See `CheckRegistry` for the per-check switches.
 */
final class Settings
{
    /**
     * @param  array<string, mixed>  $overrides
     */
    public function __construct(private readonly array $overrides = []) {}

    /**
     * @param  array<string, mixed>  $overrides
     */
    public static function fromArray(array $overrides = []): self
    {
        return new self($overrides);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->overrides[$key] ?? $default;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->overrides);
    }

    public function int(string $key, int $default): int
    {
        $value = $this->overrides[$key] ?? null;

        return is_numeric($value) ? (int) $value : $default;
    }

    public function float(string $key, float $default): float
    {
        $value = $this->overrides[$key] ?? null;

        return is_numeric($value) ? (float) $value : $default;
    }

    /**
     * Strictly a bool. A string `"false"` is NOT false — it is a wrong-typed value, and it
     * falls back to the default rather than being guessed at. Guessing here would mean a
     * configuration typo could silently enable a feature an operator meant to disable.
     */
    public function bool(string $key, bool $default): bool
    {
        $value = $this->overrides[$key] ?? null;

        return is_bool($value) ? $value : $default;
    }

    /**
     * @return list<string>
     */
    public function list(string $key): array
    {
        $value = $this->overrides[$key] ?? null;
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_map(strval(...), array_filter($value, is_scalar(...))));
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->overrides;
    }

    public function with(string $key, mixed $value): self
    {
        $overrides = $this->overrides;
        $overrides[$key] = $value;

        return new self($overrides);
    }

    // ------------------------------------------------------------------
    // The settings the engine actually reads, named once.
    //
    // Defaults are the shipped, measured values. A host that changes one takes
    // responsibility for re-measuring whatever it affects — the notes in this package's
    // README say which measurements each of these came from.
    // ------------------------------------------------------------------

    /** The master switch. OFF unless a host turns it on. */
    public function enabled(): bool
    {
        return $this->bool('enabled', false);
    }

    /** Whether a browser that sends no claims is recorded at all. */
    public function recordDeclines(): bool
    {
        return $this->bool('record_declines', true);
    }

    /**
     * Claim-body ceiling, bytes. 24 KiB: the same default as the application
     * (`security.fingerprint.max_body_bytes`, `IdentifyDeviceRequest::MAX_BODY_BYTES`) and
     * the collector's own `MAX_PAYLOAD_BYTES`, so a body the client agrees to send is one the
     * server agrees to read. 16 KiB until notes/22, when the identify body measured 15.1 KB
     * in a bare container.
     */
    public function maxBodyBytes(): int
    {
        return $this->int('max_body_bytes', 24576);
    }

    /** Challenge lifetime, seconds. A spent challenge is a challenge that did not arrive. */
    public function challengeTtl(): int
    {
        return $this->int('challenge_ttl', 300);
    }

    /** Device cookie lifetime, days. */
    public function cookieDays(): int
    {
        return $this->int('cookie_days', 400);
    }

    /** Observation retention, days. */
    public function retentionDays(): int
    {
        return $this->int('retention_days', 30);
    }

    /** Score at or above which a device is blocked. */
    public function blockThreshold(): int
    {
        return $this->int('block_threshold', 80);
    }

    /** Score at or above which a device is challenged. */
    public function challengeThreshold(): int
    {
        return $this->int('challenge_threshold', 40);
    }

    /**
     * The HMAC key for device-key derivation.
     *
     * Returns null when absent or short, and callers treat null as "do not derive a key"
     * rather than shipping an unkeyed hash. An unkeyed key would be a public function of the
     * claims, which is the exact weakness a keyed key exists to remove.
     */
    public function deviceKeySecret(): ?string
    {
        $value = $this->overrides['device_key_secret'] ?? null;

        return is_string($value) && strlen($value) >= 32 ? $value : null;
    }

    /**
     * The shared secret for edge-signed transport evidence (header order and JA4).
     */
    public function transportSecret(): ?string
    {
        $value = $this->overrides['transport_secret'] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Proxies permitted to supply an UNSIGNED JA4, for a CDN that cannot sign (Cloudflare
     * publishes `cf.botManagement.ja4Hash` and cannot sign it).
     *
     * Empty by default, and an empty list means an unsigned value from ANYONE is refused —
     * including an attacker who sets `X-Forwarded-For: 127.0.0.1`. A signed value never
     * consults this list, so adding a CDN does not weaken the signed path.
     *
     * @return list<string>
     */
    public function ja4TrustedProxies(): array
    {
        return $this->list('ja4_trusted_proxies');
    }
}

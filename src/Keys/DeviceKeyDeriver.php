<?php

declare(strict_types=1);

namespace DeviceId\Keys;

use DeviceId\Canonicaliser;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;
use DeviceId\Support\DeviceKey;
use DeviceId\Support\ProbeEnvelope;
use DeviceId\Support\TransportIntegrityResult;

/**
 * Derives the two device keys from a claim set.
 *
 * - `browser_key` = HMAC(scoped secret, canonical(stabilised tier-1 claims)). Volatile
 *   paths (window geometry, media preferences, version strings, tamper evidence), USER
 *   PREFERENCES (language, Do Not Track, PDF viewer, cookies — round-2 decision G-D3i: a
 *   setting is not identity), the per-engine navigator constants (`appName`, `vendor`…),
 *   the document prototype count (touch-dependent), the time-zone-dependent date parses
 *   and every hardware probe are removed first, so a browser update, a resize, a zoom, a
 *   language change or a flight does not re-key. It is the legacy `device_key`.
 * - `hardware_key` = HMAC(scoped secret, canonical(hard components)) over
 *   `DeviceComponents::HARD` ({os, arch, touch}); null unless all three are known (G-D2i).
 *
 * Both keys are keyed under a secret that never leaves the server and is scoped per
 * organisation, so neither is a public function of the claims. A missing or short
 * secret yields null rather than an unkeyed hash.
 */
final class DeviceKeyDeriver
{
    /**
     * Keys stripped wherever they appear: measurements and envelope bookkeeping.
     *
     * @var list<string>
     */
    private const MEASUREMENT_KEYS = ['elapsedMs', 'timing', 'budgetMs', 'digest', 'v', 'version'];

    /**
     * Top-level paths outside the identity: the whole tier-2 block (its probes are
     * engine-level or hardware-level and are keyed elsewhere), tamper evidence, and the
     * envelope fields.
     *
     * @var list<string>
     */
    private const EXCLUDED_PATHS = ['timing', 'digest', 'nonce', 'exp', 'v', 'version', 'purpose', 'slot', 'integrity', 'tier2'];

    /**
     * Tier-1 probes excluded from `browser_key`: user preferences, window state, the
     * hardware probe, and the engine-identity marks.
     *
     * `engineIdentity` is excluded for two reasons. It is a consistency input (the rule
     * `ua_vs_engine` compares it with the User-Agent), not a device fact: every V8 on
     * earth reports the same marks, so hashing it adds nothing to the key. And adding
     * any tier-1 probe to the hash re-keys every device on deploy (value-probes.ts,
     * "Adding a probe here RE-KEYS EVERY EXISTING DEVICE"); excluding it is what makes
     * shipping it a no-op for existing keys.
     *
     * @var list<string>
     */
    private const EXCLUDED_TIER1_PROBES = ['cssMedia', 'architecture', 'engineIdentity'];

    /**
     * Logical paths inside `tier1.environment` excluded from `browser_key`.
     *
     * @var list<string>
     */
    private const EXCLUDED_ENVIRONMENT_KEYS = ['viewport'];

    /** @var list<string> */
    private const EXCLUDED_SCREEN_KEYS = ['availWidth', 'availHeight', 'availLeft', 'availTop'];

    /** @var list<string> */
    private const EXCLUDED_HIGH_ENTROPY_HINTS = ['uaFullVersion', 'fullVersionList', 'platformVersion'];

    /** Identity strings whose version numbers are replaced by `N`. */
    private const VERSION_STRIPPED_IDENTITY = ['userAgent', 'appVersion'];

    /**
     * `tier1.environment.identity` fields excluded from `browser_key` (G-D3i): user
     * preferences, which a person changes without changing device, and the navigator
     * constants every build of an engine reports alike, which add nothing to a key but
     * change with engine policy (`doNotTrack` is deprecated and already gone from some
     * builds). All of them stay in the claim set as consistency inputs for the rules.
     *
     * @var list<string>
     */
    private const EXCLUDED_IDENTITY_KEYS = [
        'doNotTrack', 'language', 'languages', 'pdfViewerEnabled', 'cookieEnabled',
        'appName', 'appCodeName', 'product', 'productSub', 'vendor', 'vendorSub',
    ];

    /**
     * `tier1.objectShape` fields excluded: the Document prototype count moves with touch
     * emulation (measured, round-1 BR-15); `navigator` and `screen` stay.
     *
     * @var list<string>
     */
    private const EXCLUDED_OBJECT_SHAPE_KEYS = ['document'];

    /**
     * A `dateParsing` input whose result is independent of the time zone: it carries an
     * explicit zone (`Z`, `GMT`, `+05:30`, `-08`) or is a date-only ISO form (parsed as
     * UTC by every engine). The other inputs (`2024-01-15T10:20:30`, `January 15, 2024`,
     * `2024/01/15`…) are local-time forms whose value embeds the UTC offset, so a flight
     * re-keyed the browser (round-1 BR-11); for those only "parsed or NaN" is kept, which
     * is the engine quirk the probe exists for.
     */
    private const TIMEZONE_INDEPENDENT_DATE_INPUT = '/(Z|GMT|[+-]\d{2}(:?\d{2})?)$|^\d{4}-\d{2}-\d{2}$|^\d{4}-\d{2}$|^\d{4}$/';

    /**
     * The scoped HMAC key, or null when no usable secret is configured.
     */
    public function secret(?int $organizationId = null): ?string
    {
        $configured = Config::raw('fingerprint.device_key_secret');

        if (! is_string($configured) || strlen($configured) < 32) {
            return null;
        }

        $scope = $organizationId === null ? 'global' : 'org:'.$organizationId;

        return hash_hmac('sha256', $scope, $configured, true);
    }

    /**
     * The generation of the configured secret, masked to fit a signed smallint.
     */
    public function saltVersion(?int $organizationId = null): int
    {
        $secret = $this->secret($organizationId);

        if ($secret === null) {
            return 0;
        }

        return (int) hexdec(substr(hash('sha256', $secret), 0, 4)) & 0x7FFF;
    }

    /**
     * Both keys, the components and the coverage for one claim set, or null when no
     * secret is configured.
     *
     * @param  array<array-key, mixed>  $claims
     */
    public function keys(array $claims, TransportIntegrityResult $transport, ?int $organizationId = null): ?DeviceKeys
    {
        $secret = $this->secret($organizationId);

        if ($secret === null) {
            return null;
        }

        $untrusted = DeviceComponents::untrusted($claims, $transport);
        $components = DeviceComponents::fromClaims($claims, $transport, $secret, $untrusted);
        $browser = $this->derive($claims, $organizationId);

        return new DeviceKeys(
            $browser?->key,
            $this->hardwareKey($components, $organizationId),
            $components,
            DeviceComponents::coverage($components, DeviceComponents::engineFor($claims, $transport)),
            $this->saltVersion($organizationId),
            DeviceComponents::protectedGecko($claims, $transport),
            $untrusted,
            $this->hardwareIdentity($claims, $transport, $organizationId),
        );
    }

    /**
     * The browser key for a claim set, or null when it cannot be keyed.
     *
     * @param  array<array-key, mixed>  $claims
     */
    public function derive(array $claims, ?int $organizationId = null): ?DeviceKey
    {
        $secret = $this->secret($organizationId);

        if ($secret === null) {
            return null;
        }

        $canonical = Canonicaliser::canonicalise($this->stabilise($claims));

        return new DeviceKey(
            hash_hmac('sha256', $canonical, $secret),
            $this->saltVersion($organizationId),
        );
    }

    /**
     * The hardware key over the hard components, or null when any of them is unknown or
     * no secret is configured. Never a hash over a null (G-D2i).
     *
     * @param  array<array-key, mixed>  $components
     */
    public function hardwareKey(array $components, ?int $organizationId = null): ?string
    {
        $secret = $this->secret($organizationId);

        if ($secret === null || ! DeviceComponents::allHardKnown($components)) {
            return null;
        }

        return hash_hmac('sha256', 'hardware:'.Canonicaliser::canonicalise(DeviceComponents::hard($components)), $secret);
    }

    /**
     * The hardware identity: HMAC(scoped secret, canonical measured `HARDWARE_IDENTITY`
     * components), for a host's one-vote-per-hardware correlation (welzolekker's vote dedupe).
     *
     * ## No client flag can change it (skeptical review M1)
     *
     * The components are measured WITHOUT the trust projection's client-reported inputs
     * (`canvasFill.exact`, `canvasPattern.exact`, wrapped read-back functions, the realm
     * comparison): each is one value in the client's body, and nulling components on it let one
     * bit pick a different identity. Only a protection the ENGINE evidence proves changes the
     * answer, and then to null rather than to a hash: Firefox resistFingerprinting or Tor
     * (`protectedGecko()`) reports the protection's constants, Brave (`protectedBrave()`) farbles
     * per session, so neither has a stable hardware identity. A host must give a null identity a
     * policy at least as strict as a known one (for example a per-network rule), or declining
     * becomes the evasion.
     *
     * An honest noise extension that varies its noise per session gives a different identity per
     * session; the same is true of any client that forges a measurement. That is the limit of any
     * hash over client-measured values: use it as one correlation signal, never as the only
     * dedupe key.
     *
     * @param  array<array-key, mixed>  $claims
     */
    public function hardwareIdentity(array $claims, TransportIntegrityResult $transport, ?int $organizationId = null): ?string
    {
        $secret = $this->secret($organizationId);
        if ($secret === null
            || DeviceComponents::protectedGecko($claims, $transport)
            || EnvironmentConsistency::protectedBrave($claims, $transport)) {
            return null;
        }

        $measured = DeviceComponents::fromClaims($claims, $transport, $secret, []);
        $values = [];
        foreach (DeviceComponents::HARDWARE_IDENTITY as $name) {
            if (($measured[$name] ?? null) !== null) {
                $values[$name] = $measured[$name];
            }
        }

        return $values === [] ? null : hash_hmac('sha256', 'hardware-identity:'.Canonicaliser::canonicalise($values), $secret);
    }

    /**
     * The claim set with every volatile or non-identity path removed.
     *
     * @param  array<array-key, mixed>  $claims
     * @return array<array-key, mixed>
     */
    public function stabilise(array $claims): array
    {
        foreach (self::EXCLUDED_PATHS as $path) {
            unset($claims[$path]);
        }

        $claims = $this->stripMeasurementKeys($claims);

        $tier1 = $this->unwrap($claims['tier1'] ?? null);
        if (! is_array($tier1)) {
            unset($claims['tier1']);

            return $claims;
        }

        foreach (self::EXCLUDED_TIER1_PROBES as $probe) {
            unset($tier1[$probe]);
        }

        $environment = $this->unwrap($tier1['environment'] ?? null);
        if (is_array($environment)) {
            foreach (self::EXCLUDED_ENVIRONMENT_KEYS as $key) {
                unset($environment[$key]);
            }

            $screen = $this->unwrap($environment['screen'] ?? null);
            if (is_array($screen)) {
                foreach (self::EXCLUDED_SCREEN_KEYS as $key) {
                    unset($screen[$key]);
                }
                $environment['screen'] = $screen;
            }

            $identity = $this->unwrap($environment['identity'] ?? null);
            if (is_array($identity)) {
                foreach (self::EXCLUDED_IDENTITY_KEYS as $key) {
                    unset($identity[$key]);
                }
                foreach (self::VERSION_STRIPPED_IDENTITY as $key) {
                    if (is_string($identity[$key] ?? null)) {
                        $identity[$key] = preg_replace('/\d+(\.\d+)+/', 'N', $identity[$key]) ?? $identity[$key];
                    }
                }
                $environment['identity'] = $identity;
            }

            $tier1['environment'] = $environment;
        }

        $shape = $this->unwrap($tier1['objectShape'] ?? null);
        if (is_array($shape)) {
            foreach (self::EXCLUDED_OBJECT_SHAPE_KEYS as $key) {
                unset($shape[$key]);
            }
            $tier1['objectShape'] = $shape;
        }

        $dates = $this->unwrap($tier1['dateParsing'] ?? null);
        if (is_array($dates)) {
            $tier1['dateParsing'] = $this->timezoneIndependentDates($dates);
        }

        $hints = $this->unwrap($tier1['uaClientHints'] ?? null);
        if (is_array($hints)) {
            $high = $this->unwrap($hints['high'] ?? null);
            if (is_array($high)) {
                foreach (self::EXCLUDED_HIGH_ENTROPY_HINTS as $key) {
                    unset($high[$key]);
                }
                $hints['high'] = $high;
            }
            $tier1['uaClientHints'] = $hints;
        }

        $claims['tier1'] = $tier1;

        return $claims;
    }

    /**
     * The `dateParsing` map with every time-zone-dependent value reduced to `parsed`
     * (see TIMEZONE_INDEPENDENT_DATE_INPUT); `NaN` and the zone-carrying results are kept
     * verbatim, so the engine's parse quirks survive and the UTC offset does not.
     *
     * @param  array<array-key, mixed>  $dates
     * @return array<array-key, mixed>
     */
    private function timezoneIndependentDates(array $dates): array
    {
        $out = [];
        foreach ($dates as $input => $result) {
            $key = (string) $input;
            if (preg_match(self::TIMEZONE_INDEPENDENT_DATE_INPUT, $key) === 1 || ! is_string($result) || $result === 'NaN') {
                $out[$key] = $result;

                continue;
            }

            $out[$key] = 'parsed';
        }

        return $out;
    }

    /**
     * A probe node's value, through the envelope when there is one (ProbeEnvelope: the
     * one reader of the wire format).
     */
    private function unwrap(mixed $node): mixed
    {
        return ProbeEnvelope::unwrap($node);
    }

    /**
     * @param  array<array-key, mixed>  $value
     * @return array<array-key, mixed>
     */
    private function stripMeasurementKeys(array $value): array
    {
        $out = [];
        foreach ($value as $key => $item) {
            if (is_string($key) && in_array($key, self::MEASUREMENT_KEYS, true)) {
                continue;
            }

            $out[$key] = is_array($item) ? $this->stripMeasurementKeys($item) : $item;
        }

        return $out;
    }
}

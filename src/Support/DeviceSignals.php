<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Support;

use NutriCompare\Fingerprint\Rules\EnvironmentConsistency;
use NutriCompare\Fingerprint\Rules\IntegrityFindings;

/**
 * The browser signals the device risk rules read, and nothing else.
 *
 * Signals reach the server two ways: the page's identify call (a v3 claim set
 * from the in-house collector, mapped by {@see self::fromClaims()}) and, for
 * API clients and pages loaded before the identity layer, an
 * `X-Device-Signals` header or a `device_signals` field
 * (DeviceIdentityResolver::currentFingerprint()). The second path used to
 * keep whatever JSON arrived, up to 16 KB, and it ends up in
 * `device_fingerprints.raw_signals` — storage of arbitrary client data with
 * no purpose. Both paths now keep exactly the keys below.
 *
 * Accepted shape (what the page sends and what is stored):
 *
 *   userAgent: { platform?: string|null (<=64), maxTouchPoints?: int 0..1000 }
 *   webgl:     { vendor?: string|null (<=255), renderer?: string|null (<=255) }
 *   screen:    { width?: int 0..100000, height?: int 0..100000 }
 *   timezone:  { timezone?: string|null (<=64) }
 *   automation: { webdriver?: int 0..1, integrityFindings?: int 0..1000 }
 *
 * `automation` (round-2 FR2-5) carries the collector's two strongest automation
 * markers to the risk rules: whether `navigator.webdriver` was true, and how many
 * integrity findings held for the claim set (the client's own plus the ones the server
 * derives from its data, `IntegrityFindings::effective()`). Two small integers, no
 * values. Only the identify path produces them; a client-sent signal set may carry
 * them too, bounded like everything else.
 *
 * The flat legacy keys `platform`, `maxTouchPoints` and a flat `timezone`,
 * which the risk rules also read, are accepted and stored in that nested shape.
 *
 * ## Bounding a value must not change the verdict
 *
 * The rules (DeviceFingerprintRiskEvaluator) read these values loosely, and a
 * value outside the bounds is itself evidence: 5000 touch points on a desktop
 * is the touch mismatch, a screen sent as a string is headless, a time zone
 * that is not text is an anomaly. So an out-of-bounds value is brought inside
 * the bounds, not thrown away — a number is cast as the rules cast it and then
 * clamped, a string is cut to its length, a time zone that is not text is
 * stored as blank — and the rules reach the same conclusion from what is
 * stored as they would have from what was sent (DeviceSignalsVerdictTest
 * holds that). The one exception is text longer than its limit: it is cut,
 * and a marker past the cut is lost — no browser reports a renderer or a
 * time zone that long. Text that is not valid UTF-8 has its bad bytes
 * replaced; it used to make the row unencodable and the request fail.
 *
 * One read is deliberately gone: `userAgent.userAgent`, the page's copy of the
 * full user-agent string. The rules read the request's own User-Agent header;
 * the copy only mattered for a request that sent no header at all, and a full
 * user-agent string is exactly what UserAgentSummary exists to avoid storing.
 */
final class DeviceSignals
{
    /** @var array<string, array<string, array{0: 'string'|'int', 1: int, 2?: int}>> */
    private const SHAPE = [
        'userAgent' => ['platform' => ['string', 64], 'maxTouchPoints' => ['int', 0, 1000]],
        'webgl' => ['vendor' => ['string', 255], 'renderer' => ['string', 255]],
        'screen' => ['width' => ['int', 0, 100000], 'height' => ['int', 0, 100000]],
        'timezone' => ['timezone' => ['string', 64]],
        'automation' => ['webdriver' => ['int', 0, 1], 'integrityFindings' => ['int', 0, 1000]],
    ];

    /** @var array<string, array{0: string, 1: string, 2: array{0: 'string'|'int', 1: int, 2?: int}}> flat key => [group, key, rule] */
    private const LEGACY = [
        'platform' => ['userAgent', 'platform', ['string', 64]],
        'maxTouchPoints' => ['userAgent', 'maxTouchPoints', ['int', 0, 1000]],
        'timezone' => ['timezone', 'timezone', ['string', 64]],
    ];

    /**
     * The signals a v3 claim set carries (resources/js/v3), in
     * the shape above:
     *
     *   platform       <- tier1.environment.identity.platform
     *   maxTouchPoints <- tier1.environment.identity.maxTouchPoints
     *   screen         <- tier1.environment.screen.width / height
     *   timezone       <- tier2.intl.timeZone.name
     *   webgl          <- tier2.gpu.webgl.vendor / renderer
     *   automation     <- tier1.environment.identity.webdriver, IntegrityFindings::effective()
     *
     * A probe that failed (`{state: 'error'}`) or was not collected reads as
     * absent (EnvironmentConsistency::read() unwraps the probe envelope), and an
     * absent group is left out — the rules read `screen` by presence, so a
     * claim set without a screen says nothing about one rather than "0×0".
     * Every value then goes through {@see self::sanitize()} like a client-sent
     * signal would.
     *
     * @param  array<array-key, mixed>  $claims
     * @return array<string, array<string, int|string|null>>
     */
    public static function fromClaims(array $claims): array
    {
        $raw = [];

        $platform = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'platform');
        $touch = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'maxTouchPoints');
        if (is_string($platform) || is_numeric($touch)) {
            $raw['userAgent'] = array_filter(
                ['platform' => is_string($platform) ? $platform : null, 'maxTouchPoints' => is_numeric($touch) ? $touch : null],
                static fn (mixed $value): bool => $value !== null,
            );
        }

        $width = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'screen', 'width');
        $height = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'screen', 'height');
        if (is_numeric($width) || is_numeric($height)) {
            $raw['screen'] = array_filter(
                ['width' => is_numeric($width) ? $width : null, 'height' => is_numeric($height) ? $height : null],
                static fn (mixed $value): bool => $value !== null,
            );
        }

        $timezone = EnvironmentConsistency::read($claims, 'tier2', 'intl', 'timeZone', 'name');
        if (is_string($timezone)) {
            $raw['timezone'] = ['timezone' => $timezone];
        }

        $webgl = EnvironmentConsistency::read($claims, 'tier2', 'gpu', 'webgl');
        if (is_array($webgl)) {
            $vendor = $webgl['vendor'] ?? null;
            $renderer = $webgl['renderer'] ?? null;
            if (is_string($vendor) || is_string($renderer)) {
                $raw['webgl'] = array_filter(
                    ['vendor' => is_string($vendor) ? $vendor : null, 'renderer' => is_string($renderer) ? $renderer : null],
                    static fn (mixed $value): bool => $value !== null,
                );
            }
        }

        $webdriver = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'webdriver');
        $automation = [];
        if (is_bool($webdriver)) {
            $automation['webdriver'] = $webdriver ? 1 : 0;
        }
        if (is_array($claims['integrity'] ?? null)) {
            $automation['integrityFindings'] = count(IntegrityFindings::effective($claims));
        }
        if ($automation !== []) {
            $raw['automation'] = $automation;
        }

        return self::sanitize($raw);
    }

    /**
     * @param  array<array-key, mixed>  $raw
     * @return array<string, array<string, int|string|null>>
     */
    public static function sanitize(array $raw): array
    {
        $out = [];

        foreach (self::SHAPE as $group => $fields) {
            if (! array_key_exists($group, $raw)) {
                continue;
            }

            $values = $raw[$group];

            if (! is_array($values)) {
                // The rules read `screen` by presence: sent at all, a missing
                // size counts as zero, which is headless. So a screen sent as
                // something other than an object stays a present, empty group.
                // (A flat `timezone` string is a legacy key, handled below; the
                // other groups say nothing unless they are objects.)
                if ($group === 'screen') {
                    $out['screen'] = [];
                }

                continue;
            }

            // A group the client sent, even emptied, still says something the
            // rules read (a present, empty `screen` is headless).
            $out[$group] = [];

            foreach ($fields as $key => $rule) {
                if (array_key_exists($key, $values) && self::normalise($values[$key], $rule, $group === 'timezone', $clean)) {
                    $out[$group][$key] = $clean;
                }
            }
        }

        foreach (self::LEGACY as $flat => [$group, $key, $rule]) {
            if (! array_key_exists($flat, $raw) || is_array($raw[$flat]) || array_key_exists($key, $out[$group] ?? [])) {
                continue;
            }

            // A flat null said nothing to the rules (they only look for a
            // value), so it is not stored as one.
            if ($raw[$flat] === null) {
                continue;
            }

            if (self::normalise($raw[$flat], $rule, $group === 'timezone', $clean)) {
                $out[$group][$key] = $clean;
            }
        }

        return $out;
    }

    /**
     * Bring `$value` inside `$rule` the way the rules would read it; false
     * when there is nothing to keep (the rules would read it as absent).
     *
     * - Text: null stays null; a string is cut to the rule's length (bad UTF-8
     *   bytes replaced). Anything else is absent — except a time zone, which
     *   the rules call an anomaly when it is not text, so it is kept as blank.
     * - Numbers: anything numeric is cast to an integer, as the rules cast it
     *   (a digit string from a form post included), then clamped to the range.
     *
     * @param  array{0: 'string'|'int', 1: int, 2?: int}  $rule
     */
    private static function normalise(mixed $value, array $rule, bool $blankWhenNotText, int|string|null &$clean = null): bool
    {
        if ($rule[0] === 'string') {
            if ($value === null) {
                $clean = null;

                return true;
            }

            if (is_string($value)) {
                if (! mb_check_encoding($value, 'UTF-8')) {
                    $value = mb_scrub($value, 'UTF-8');
                }

                $clean = mb_substr($value, 0, $rule[1]);

                return true;
            }

            if ($blankWhenNotText) {
                $clean = '';

                return true;
            }

            return false;
        }

        if (! is_numeric($value)) {
            return false;
        }

        $clean = max($rule[1], min($rule[2] ?? PHP_INT_MAX, (int) $value));

        return true;
    }
}

<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Keys;

use NutriCompare\Fingerprint\Rules\EnvironmentConsistency;
use NutriCompare\Fingerprint\Rules\IntegrityFindings;
use NutriCompare\Fingerprint\Support\TransportIntegrityResult;

/**
 * Quantises a claim set into the engine-independent component map the matcher scores.
 *
 * Every component is `null` when its input is absent or malformed. Null means "not
 * known", never a default: a default would make two devices that both lacked a probe
 * agree on it. Only the quantised classes and keyed hashes are returned; no raw claim
 * value (font names, renderer strings, pair lists) leaves this class.
 *
 * Hard components (`HARD`) form `hardware_key` and the indexed `block_tuple`; soft
 * components (`SOFT`) are scored by `DeviceMatcher` for partial agreement.
 */
final class DeviceComponents
{
    /**
     * The hard components: what every browser on one machine reports alike AND what a
     * display change, a headset or a user setting cannot move — the OS family (header
     * witness first, User-Agent family second), the CPU architecture and whether the device
     * has a touch screen. `hardware_key` is an HMAC over exactly these three, and only when
     * all three are known (round-2 decision G-D2i). Everything that describes the current
     * monitor or audio output (`aspect`, `panel`, `display`, `audio`), the core count (capped
     * by Safari) and the rest are SOFT: scored by `DeviceMatcher`, never keyed.
     *
     * @var list<string>
     */
    public const HARD = ['os', 'arch', 'touch'];

    /**
     * Soft components, scored for partial agreement. Order matters in two places: `gpu`
     * precedes `gpuMath`, which is consulted only where the engine-conditioned `gpu`
     * class could say nothing (two engines, notes/22 M1); and the list is the storage
     * order of the component map.
     *
     * `osVersion` (the major from `Sec-CH-UA-Platform-Version`) is soft, not part of `os`:
     * only Chromium sends the hint, so folding it into the hard key would split the same
     * machine between Chromium and Firefox.
     *
     * @var list<string>
     */
    public const SOFT = ['cores', 'aspect', 'panel', 'display', 'audio', 'fonts', 'emoji', 'scripts', 'gpu', 'voices', 'decoders', 'memory', 'osVersion', 'gpuMath'];

    /**
     * Auxiliary values stored beside the components but never scored or keyed: the font
     * pair count, and the engine family (`chromium`|`gecko`|`webkit`) the matcher reads to
     * make `cores` neutral where Safari caps `hardwareConcurrency`.
     *
     * @var list<string>
     */
    public const AUXILIARY = ['fontsCount', 'engine'];

    /**
     * The components a protected browser ({@see protectedGecko()}) reports as constants of the
     * protection rather than of the device: the spoofed screen (`aspect`, `display`, `panel`),
     * core count, touch, User-Agent OS (`os`, `osVersion`), WebGL (`gpu`, `memory`), the
     * randomised canvas path (`fonts`, `emoji`, `scripts`, `fontsCount`) and the read-back
     * shader class (`gpuMath`). `audio`, `arch`, `decoders` and `voices` stay. With `os` and
     * `touch` absent no `hardware_key` is derived from a protection's constants.
     *
     * @var list<string>
     */
    public const PROTECTED_UNTRUSTED = ['fonts', 'emoji', 'scripts', 'fontsCount', 'os', 'osVersion', 'cores', 'touch', 'aspect', 'display', 'panel', 'gpu', 'memory', 'gpuMath'];

    /**
     * Every hard component must be known for `hardware_key` (G-D2i: a null is never hashed,
     * so a tier-1-only visit and a full visit of one browser derive the same key).
     */
    public const MIN_HARD_FOR_KEY = 3;

    /** The sha256 input separator for `block_tuple` (os|arch|touch). */
    private const BLOCK_TUPLE_SEPARATOR = '|';

    /**
     * Known physical panel widths (px). `panel` snaps to the nearest within 4 %.
     *
     * @var list<int>
     */
    public const PANELS = [1280, 1366, 1440, 1536, 1600, 1680, 1920, 2048, 2160, 2560, 2732, 2880, 3024, 3072, 3200, 3440, 3456, 3840, 4096, 5120, 6016];

    /** Width rounding when no known panel is within 4 %. */
    private const PANEL_STEP = 40;

    /** ~60 families × up to 11 chars; a longer `pairs` string is not the client's. */
    private const FONTS_MAX_LENGTH = 1024;

    /**
     * Landscape-normalised panel ratios snapped to within 1 %.
     *
     * @var list<array{0: int, 1: int}>
     */
    private const COMMON_RATIOS = [[16, 9], [16, 10], [3, 2], [4, 3], [5, 4], [21, 9], [32, 9], [19, 9], [20, 9], [13, 6], [2, 1]];

    /** `emoji` bucket width in CSS px. */
    private const EMOJI_BUCKET = 4;

    /**
     * Bit positions in the client's `cssMedia` string (value-probes.ts `cssMedia()`),
     * for the `display` component.
     */
    private const CSS_DYNAMIC_RANGE_HIGH = 11;

    private const CSS_GAMUT_SRGB = 13;

    private const CSS_GAMUT_P3 = 14;

    private const CSS_GAMUT_REC2020 = 15;

    /**
     * The client's `cssMedia` string is 24 bits; a shorter one is not the client's. The
     * highest bit read here is 15, the pointer bits `EnvironmentConsistency` reads are 22.
     */
    private const CSS_MIN_LENGTH = 23;

    /**
     * @return list<string>
     */
    public static function names(): array
    {
        return [...self::HARD, ...self::SOFT];
    }

    /**
     * The component map for one claim set.
     *
     * @param  array<array-key, mixed>  $claims  a decoded, probe-wrapped or unwrapped claim set
     * @param  string|null  $secret  the scoped HMAC secret for the keyed `gpu` hash; without it that
     *                               component is null rather than unkeyed
     * @param  list<string>|null  $untrusted  `untrusted()` for this claim set when the caller already
     *                                        computed it (`DeviceKeyDeriver::keys()` keeps it on `DeviceKeys`)
     * @return array<string, scalar|null>
     */
    public static function fromClaims(array $claims, TransportIntegrityResult $transport, ?string $secret = null, ?array $untrusted = null): array
    {
        $userAgent = self::userAgent($claims, $transport);
        $engine = $userAgent === null ? null : EnvironmentConsistency::uaEngineFamily($userAgent);

        $screenWidth = self::int(EnvironmentConsistency::read($claims, 'tier1', 'environment', 'screen', 'width'));
        $screenHeight = self::int(EnvironmentConsistency::read($claims, 'tier1', 'environment', 'screen', 'height'));

        $components = [
            'os' => self::os($claims, $transport, $userAgent),
            'osVersion' => self::osVersion($transport),
            'arch' => self::arch($claims, $transport),
            'cores' => self::cores(EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'hardwareConcurrency')),
            'touch' => self::touch(EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'maxTouchPoints')),
            'aspect' => self::aspect($screenWidth, $screenHeight),
            'display' => self::display(EnvironmentConsistency::read($claims, 'tier1', 'cssMedia')),
            'audio' => self::audio($claims),
            'panel' => self::panel($screenWidth, $screenHeight, EnvironmentConsistency::read($claims, 'tier1', 'environment', 'viewport', 'devicePixelRatio')),
            'fonts' => self::fonts($claims, $secret),
            'emoji' => self::emoji(EnvironmentConsistency::read($claims, 'tier2', 'emojiMetrics', 'width')),
            'scripts' => self::bits(EnvironmentConsistency::read($claims, 'tier2', 'scripts', 'bits')),
            'gpu' => self::gpu($claims, $engine, $secret),
            'voices' => self::voices($claims, $secret),
            'decoders' => self::decoders($claims),
            'memory' => self::memory(EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'deviceMemory')),
            'gpuMath' => self::gpuMath($claims, $secret),
            'fontsCount' => self::int(EnvironmentConsistency::read($claims, 'tier2', 'fontMetrics', 'count')),
            'engine' => $engine,
        ];

        foreach ($untrusted ?? self::untrusted($claims, $transport) as $name) {
            $components[$name] = null;
        }

        return $components;
    }

    /**
     * Components the claim set itself says cannot be trusted as device identity, so they
     * are reported as ABSENT rather than matched.
     *
     * CreepJS's one reusable design idea (notes/21 §1): a component flagged as lied or as
     * noised is left OUT of the stable id, so tampering removes entropy instead of
     * forking the identity. Here the flags are the client's own read-back findings and
     * its resistance report:
     *
     * - `canvas_readback_perturbed`: the canvas pixel path is noised, and the
     *   canvas-measured components (`fonts`, `emoji`, `scripts` and the auxiliary
     *   `fontsCount`) are measured through `measureText` on that path. Under per-session
     *   noise they are consistent within a visit and different on the next, which is
     *   exactly the fork this prevents.
     * - Firefox `resistFingerprinting` and Tor Browser spoof the screen (letterboxed
     *   window size as screen), the core count (2), touch (0), the User-Agent OS and the
     *   canvas; every component derived from those is a property of the protection, not
     *   of the device, and two such browsers on different hardware would otherwise
     *   derive the SAME hardware_key. `audio`, `arch`, `decoders` and `voices` stay: RFP
     *   does not touch the sample rate or the NaN sign, and the matcher already treats
     *   the soft ones as weak.
     * - Brave farbles WebGL parameters per session and origin, so the `gpu` class (an
     *   HMAC over precision and limits) differs on every visit.
     *
     * ## The flags are honoured only when the rest of the evidence agrees (security review)
     *
     * A resistance flag is one boolean in a client-controlled body, and "fewer matched
     * components" is precisely what a multi-account operator wants: with the hard set
     * nulled no `hardware_key` is derived and the matcher's blocking tuple is empty, and a
     * protected key set is not linked by `browser_key` either (`DeviceMatcher`), so an
     * honoured flag means a new device per visit. So `rfp`/`tor` count only under the
     * engine evidence of `EnvironmentConsistency::engineEvidence()` (the complete SpiderMonkey
     * mark set, a Gecko User-Agent in the claims and in the header, no Client-Hints header,
     * no JA4 profile of another family) — {@see protectedGecko()}, the one definition of
     * that gate; `brave` counts only when the marks and the UA say Chromium. A claim that
     * fails those checks is left trusted here AND scored by the `resistance_vs_engine`
     * rule, so faking it costs risk instead of buying anonymity. Most of that evidence is
     * client-reported (a non-browser can copy a complete honest capture); the server-observed
     * parts can only refute it — see `engineEvidence()` for the residual.
     * The canvas-fill flag is honoured as is: it reaches soft components only, the
     * hardware key stays, and a spoofer gains nothing it could not get by not sending
     * `fontMetrics` at all.
     *
     * @param  array<array-key, mixed>  $claims
     * @return list<string>
     */
    public static function untrusted(array $claims, TransportIntegrityResult $transport = new TransportIntegrityResult): array
    {
        // Reported or derived by the server from the client's own integrity data (notes/24
        // F10): a noised read-back the client stayed silent about is still untrusted.
        $codes = IntegrityFindings::effective($claims);

        ['gecko' => $geckoEvidence, 'chromium' => $chromiumEvidence] = EnvironmentConsistency::engineEvidence($claims, $transport);

        // A wrapped read-back function (lie battery / realm toString on a canvas, WebGL or
        // audio target) is a noise extension: its surface is not device identity either.
        $liedApis = [];
        foreach ([['integrity', 'data', 'lieBattery', 'lied'], ['integrity', 'data', 'phantomRealm', 'nativeToString', 'mismatched']] as $path) {
            $data = EnvironmentConsistency::read($claims, ...$path);
            foreach (is_array($data) ? $data : [] as $key => $entry) {
                $api = is_string($key) ? $key : (is_string($entry) ? $entry : null);
                if ($api !== null && EnvironmentConsistency::isNoiseSurface($api)) {
                    $liedApis[] = $api;
                }
            }
        }
        $canvasWrapped = (bool) array_filter($liedApis, static fn (string $api): bool => str_starts_with($api, 'HTMLCanvasElement.') || str_starts_with($api, 'CanvasRenderingContext2D.') || str_starts_with($api, 'OffscreenCanvas'));
        $webglWrapped = (bool) array_filter($liedApis, static fn (string $api): bool => str_contains($api, 'WebGL'));

        $protected = self::protectedUnder($geckoEvidence, $claims);
        $brave = $chromiumEvidence && EnvironmentConsistency::read($claims, 'integrity', 'data', 'resistance', 'brave') === true;
        // The finding is raised by the synchronous phase (tier-1 envelope); the deferred
        // phase re-measures the fill and reports it as data only, so the tier-2 envelope
        // — the one that carries the canvas-measured components — can be judged on its own.
        $canvasNoised = isset($codes['canvas_readback_perturbed']) || $canvasWrapped
            || EnvironmentConsistency::read($claims, 'integrity', 'data', 'canvasFill', 'exact') === false;

        $untrusted = [];
        if ($canvasNoised) {
            array_push($untrusted, 'fonts', 'emoji', 'scripts', 'fontsCount');
        }
        if ($protected) {
            array_push($untrusted, ...self::PROTECTED_UNTRUSTED);
        }
        if ($brave) {
            $untrusted[] = 'gpu';
        }
        // The shader-arithmetic class reads pixels back, and every one of these noises
        // read-back (Brave farbles readPixels; RFP and Tor randomise canvas reads, which
        // PROTECTED_UNTRUSTED already covers).
        if ($brave || $webglWrapped) {
            $untrusted[] = 'gpuMath';
        }
        if ($webglWrapped) {
            $untrusted[] = 'gpu';
        }

        return array_values(array_unique($untrusted));
    }

    /**
     * Whether this claim set comes from Firefox resistFingerprinting or Tor Browser, by its own
     * `resistance` report AND the engine evidence (`EnvironmentConsistency::engineEvidence()`:
     * the complete SpiderMonkey mark set, a Gecko User-Agent in the claims and the header, no
     * Client-Hints header, no JA4 profile of another family). Client-reported in large part,
     * so it raises the cost of the forgery and lets server-observed facts refute it; it does
     * not prove a browser.
     *
     * The ONE definition of the gate. {@see untrusted()} uses it to drop the protection's
     * constants from the component map, `DeviceKeyDeriver` uses it to mark the key set
     * protected, and `DeviceMatcher` refuses key linking for a protected set: those browsers
     * report the same tier-1 constants (letterboxed screen, spoofed cores, UTC, en-US), so
     * their `browser_key` names a cohort, not a browser profile (anti-fraud review). A
     * `rfp`/`tor` flag the evidence contradicts (a Chrome forging it) is NOT honoured here,
     * so it buys neither untrusted components nor unlinkability, and
     * `resistance_vs_engine` scores it.
     *
     * The tier-2 envelope carries no tier-1 engine marks or User-Agent (the server drops a
     * `tier1` block from it, `ClientClaimsEnvelope::signalClaims()`), so on that envelope this
     * is always false; `FingerprintIngest` takes the tier-2 decision from the device row
     * (`fingerprint_devices.protected`) alone.
     *
     * @param  array<array-key, mixed>  $claims
     */
    public static function protectedGecko(array $claims, TransportIntegrityResult $transport = new TransportIntegrityResult): bool
    {
        return EnvironmentConsistency::protectedGecko($claims, $transport);
    }

    /**
     * @param  array<array-key, mixed>  $claims
     */
    private static function protectedUnder(bool $geckoEvidence, array $claims): bool
    {
        // `EnvironmentConsistency::protectedGecko()` with the evidence already computed by the caller.
        return $geckoEvidence && EnvironmentConsistency::claimsGeckoProtection($claims);
    }

    /**
     * The GPU's transcendental arithmetic, as a keyed class (notes/22 M1).
     *
     * The client renders four amplified transcendental functions into a 4×4 target and
     * hashes the 64 bytes read back; the low mantissa bits differ per GPU, driver
     * generation and backend, and — measured on one driver through four engine/backend
     * combinations — are the SAME across browsers on the same driver, which is what
     * makes this a cross-browser component where the engine-conditioned `gpu` class is
     * not. Keyed with the precision class so highp and mediump renders never compare.
     *
     * Absent when the renderer is a software rasteriser: SwiftShader, llvmpipe, WARP and
     * their kin collapse every machine to one value, and for an agree-only component a
     * shared constant is false LINK evidence, the worst direction. The client reports
     * that fact as `software`; the hash is still sent so an operator can see it.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private static function gpuMath(array $claims, ?string $secret): ?string
    {
        if ($secret === null) {
            return null;
        }

        if (EnvironmentConsistency::read($claims, 'tier2', 'gpuMath', 'software') !== false) {
            return null;
        }

        $hash = EnvironmentConsistency::read($claims, 'tier2', 'gpuMath', 'hash');
        $precision = EnvironmentConsistency::read($claims, 'tier2', 'gpuMath', 'precision');

        if (! is_string($hash) || preg_match('/^[0-9a-f]{8}$/', $hash) !== 1
            || ! is_string($precision) || $precision === '' || strlen($precision) > 32 || preg_match('/^[a-z0-9:,-]+$/', $precision) !== 1) {
            return null;
        }

        return 'gpumath:'.self::keyed('gpuMath', $precision.'|'.$hash, $secret);
    }

    /**
     * Stored components plus a later envelope's: a non-null fresh value replaces the
     * stored one; a null fresh value never erases a known one.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  array<string, scalar|null>  $fresh
     * @return array<string, scalar|null>
     */
    public static function merge(array $stored, array $fresh): array
    {
        $out = [];
        foreach ([...self::names(), ...self::AUXILIARY] as $name) {
            $value = $fresh[$name] ?? null;
            if ($value === null) {
                $value = $stored[$name] ?? null;
            }
            $out[$name] = is_scalar($value) ? $value : null;
        }

        return $out;
    }

    /**
     * Only the hard components, in a fixed order, for `hardware_key`.
     *
     * @param  array<array-key, mixed>  $components
     * @return array<string, scalar|null>
     */
    public static function hard(array $components): array
    {
        $out = [];
        foreach (self::HARD as $name) {
            $value = $components[$name] ?? null;
            $out[$name] = is_scalar($value) ? $value : null;
        }

        return $out;
    }

    /**
     * @param  array<array-key, mixed>  $components
     */
    public static function knownHardCount(array $components): int
    {
        return count(array_filter(self::hard($components), static fn (mixed $v): bool => $v !== null));
    }

    /**
     * Whether every hard component is known: the condition for `hardware_key` and for
     * `block_tuple` (G-D2i). A key over a partial tuple would differ between a tier-1-only
     * visit and a full one of the same browser.
     *
     * @param  array<array-key, mixed>  $components
     */
    public static function allHardKnown(array $components): bool
    {
        return self::knownHardCount($components) === count(self::HARD);
    }

    /**
     * The app-written blocking column (`block_tuple`): sha256 of `os|arch|touch`, or null
     * when any of the three is unknown. Unkeyed on purpose — it is an index key, not an
     * identity: the three classes it hashes are low-entropy and already stored in
     * `components`, and an indexed column is what lets the candidate query avoid a
     * JSON-path scan of the whole window (round-2 BE2-03 / PERF-17).
     *
     * @param  array<array-key, mixed>  $components
     */
    public static function blockTuple(array $components): ?string
    {
        if (! self::allHardKnown($components)) {
            return null;
        }

        $hard = self::hard($components);

        return hash('sha256', implode(self::BLOCK_TUPLE_SEPARATOR, array_map(
            static fn (mixed $v): string => is_bool($v) ? ($v ? '1' : '0') : (string) $v,
            array_values($hard),
        )));
    }

    /**
     * The engine family recorded with a component map (`engine`), or null.
     *
     * @param  array<array-key, mixed>  $components
     */
    public static function engineOf(array $components): ?string
    {
        $engine = $components['engine'] ?? null;

        return is_string($engine) && in_array($engine, ['chromium', 'gecko', 'webkit'], true) ? $engine : null;
    }

    /**
     * Components a client of this engine is expected to report.
     *
     * `memory` (`navigator.deviceMemory`) and `osVersion` (a Client Hint) ship only in
     * Chromium, so their absence on another engine is not a coverage loss.
     *
     * @return list<string>
     */
    public static function expectedFor(?string $engine): array
    {
        $names = self::names();

        if ($engine !== 'chromium') {
            // `deviceMemory` and the `Sec-CH-UA-Platform-Version` hint (`osVersion`) ship
            // only in Chromium (round-2 R2-06: with `osVersion` expected everywhere, a
            // perfectly measured Firefox or Safari could never reach coverage 1).
            $names = array_values(array_filter($names, static fn (string $n): bool => $n !== 'memory' && $n !== 'osVersion'));
        }

        // Legitimately absent on every software renderer and wherever WebGL is off, which
        // is a large honest population; expecting it would read as missing coverage on
        // every one of them. It is a bonus where it exists, never a gap where it does not.
        return array_values(array_filter($names, static fn (string $n): bool => $n !== 'gpuMath'));
    }

    /**
     * Non-null expected components over expected components, 0..1.
     *
     * @param  array<array-key, mixed>  $components
     */
    public static function coverage(array $components, ?string $engine): float
    {
        $expected = self::expectedFor($engine);
        if ($expected === []) {
            return 0.0;
        }

        $known = 0;
        foreach ($expected as $name) {
            if (($components[$name] ?? null) !== null) {
                $known++;
            }
        }

        return round($known / count($expected), 3);
    }

    /**
     * The browser's engine family for the coverage denominator, from the claims first and
     * the request header otherwise.
     *
     * @param  array<array-key, mixed>  $claims
     */
    public static function engineFor(array $claims, TransportIntegrityResult $transport): ?string
    {
        $userAgent = self::userAgent($claims, $transport);

        return $userAgent === null ? null : EnvironmentConsistency::uaEngineFamily($userAgent);
    }

    // -----------------------------------------------------------------------
    // Hard components
    // -----------------------------------------------------------------------

    /**
     * @param  array<array-key, mixed>  $claims
     */
    private static function os(array $claims, TransportIntegrityResult $transport, ?string $userAgent): ?string
    {
        $hint = $transport->witnessString('sec_ch_ua_platform');
        $family = $hint === null ? null : self::hintPlatformFamily($hint);

        if ($family !== null) {
            return $family;
        }

        return $userAgent === null ? null : EnvironmentConsistency::uaOsFamily($userAgent);
    }

    private static function osVersion(TransportIntegrityResult $transport): ?int
    {
        $version = $transport->witnessString('sec_ch_ua_platform_version');

        return $version === null ? null : self::major(trim($version, "\" \t"));
    }

    private static function hintPlatformFamily(string $hint): ?string
    {
        return match (strtolower(trim($hint, "\" \t"))) {
            'windows' => 'windows',
            'macos' => 'macos',
            'ios' => 'ios',
            'android' => 'android',
            'linux' => 'linux',
            'chrome os', 'chromeos' => 'chromeos',
            default => null,
        };
    }

    private static function major(string $version): ?int
    {
        return preg_match('/^(\d+)/', $version, $m) === 1 ? (int) $m[1] : null;
    }

    /**
     * `x86` | `arm` from the NaN-sign probe, cross-checked with `Sec-CH-UA-Arch`. The
     * header wins when the probe is unknown; a disagreement yields null (the
     * `arch_vs_ch_arch` rule scores it).
     *
     * @param  array<array-key, mixed>  $claims
     */
    private static function arch(array $claims, TransportIntegrityResult $transport): ?string
    {
        $claimed = EnvironmentConsistency::read($claims, 'tier1', 'architecture', 'nanSign');
        $claimed = is_string($claimed) && in_array($claimed, ['x86', 'arm'], true) ? $claimed : null;

        $hint = $transport->witnessString('sec_ch_ua_arch');
        $hinted = $hint === null ? null : strtolower(trim($hint, "\" \t"));
        $hinted = in_array($hinted, ['x86', 'arm'], true) ? $hinted : null;

        if ($claimed !== null && $hinted !== null) {
            return $claimed === $hinted ? $claimed : null;
        }

        return $claimed ?? $hinted;
    }

    private static function cores(mixed $value): ?int
    {
        $cores = self::int($value);

        return ($cores !== null && $cores >= 1 && $cores <= 64) ? $cores : null;
    }

    private static function touch(mixed $value): ?int
    {
        $points = self::int($value);

        return $points === null ? null : ($points > 0 ? 1 : 0);
    }

    private static function aspect(?int $width, ?int $height): ?string
    {
        if ($width === null || $height === null || $width < 1 || $height < 1) {
            return null;
        }

        $long = max($width, $height);
        $short = min($width, $height);
        $ratio = $long / $short;

        // Snap to a common panel ratio within 1 % first: 1366×768 reduces to 683:384 by gcd
        // but is a 16:9 panel (measured on a real laptop panel, W4 notes).
        foreach (self::COMMON_RATIOS as [$a, $b]) {
            if (abs($ratio - $a / $b) <= ($a / $b) * 0.01) {
                return $a.':'.$b;
            }
        }

        $gcd = self::gcd($long, $short);

        return intdiv($long, $gcd).':'.intdiv($short, $gcd);
    }

    private static function gcd(int $a, int $b): int
    {
        while ($b !== 0) {
            [$a, $b] = [$b, $a % $b];
        }

        return max(1, $a);
    }

    /**
     * `gamut|hdr` from the `cssMedia` bits: the colour gamut class and whether the output
     * supports high dynamic range. Both describe the display the window is on, which is why
     * the component is SOFT. `colorDepth` (30 vs 24 on one Mac between two browsers),
     * `forced-colors` (a user accessibility setting) and `monochrome` are deliberately not
     * part of it any more (round-2 R2-09, FR2-3, BR2-3).
     *
     * The bit positions are the client's `cssMedia()` query order (value-probes.ts); the
     * captured-claims contract test pins them against real engines.
     */
    private static function display(mixed $cssMedia): ?string
    {
        if (! is_string($cssMedia) || strlen($cssMedia) < self::CSS_MIN_LENGTH || preg_match('/^[01]+$/', $cssMedia) !== 1) {
            return null;
        }

        $bit = static fn (int $index): string => $cssMedia[$index] === '1' ? '1' : '0';

        $gamut = match (true) {
            $bit(self::CSS_GAMUT_REC2020) === '1' => 'rec2020',
            $bit(self::CSS_GAMUT_P3) === '1' => 'p3',
            $bit(self::CSS_GAMUT_SRGB) === '1' => 'srgb',
            default => 'none',
        };

        return $gamut.'|'.$bit(self::CSS_DYNAMIC_RANGE_HIGH);
    }

    /**
     * The output sample rate from `audioRealtime`, else `audioHardware`. The channel count is
     * not part of it: Firefox and WebKit report `maxChannelCount` 0 where Chromium reports 2
     * on one machine (measured, round-2 BR2-3), and a 0 means no output device at all, in
     * which case the rate is a default rather than a measurement — absent.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private static function audio(array $claims): ?string
    {
        foreach (['audioRealtime', 'audioHardware'] as $probe) {
            $rate = self::int(EnvironmentConsistency::read($claims, 'tier2', $probe, 'sampleRate'));
            $channels = self::int(EnvironmentConsistency::read($claims, 'tier2', $probe, 'maxChannelCount'));

            if ($rate !== null && $rate > 0 && ($channels === null || $channels > 0)) {
                return (string) $rate;
            }
        }

        return null;
    }

    // -----------------------------------------------------------------------
    // Soft components
    // -----------------------------------------------------------------------

    private static function panel(?int $width, ?int $height, mixed $ratio): ?int
    {
        if ($width === null || $height === null || $width < 1 || $height < 1) {
            return null;
        }

        if (! is_int($ratio) && ! is_float($ratio)) {
            return null;
        }

        if ($ratio <= 0 || $ratio > 10) {
            return null;
        }

        $physical = (int) round(max($width, $height) * $ratio);

        $nearest = null;
        $distance = PHP_INT_MAX;
        foreach (self::PANELS as $panel) {
            $delta = abs($panel - $physical);
            if ($delta < $distance) {
                $distance = $delta;
                $nearest = $panel;
            }
        }

        if ($nearest !== null && $distance <= $nearest * 0.04) {
            return $nearest;
        }

        return (int) (round($physical / self::PANEL_STEP) * self::PANEL_STEP);
    }

    /**
     * The font set as sorted, de-duplicated per-pair HMAC tokens (`fonts\0w1:w2` under the
     * scoped secret, first 8 hex each, joined by `,`). Jaccard is invariant under a
     * per-element injective map, so the matcher scores the token sets exactly as it would
     * the raw pairs — but nothing portable is stored: the raw pair list could be re-matched
     * by anyone running the shipped probe (security review SEC2-3). Cross-engine Jaccard on
     * one Linux machine measured 0.8 (8 of 10 pairs shared), exactly the agree threshold.
     * Null without a secret, like the other keyed components. Bounded in length and shape.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private static function fonts(array $claims, ?string $secret): ?string
    {
        $pairs = EnvironmentConsistency::read($claims, 'tier2', 'fontMetrics', 'pairs');

        if ($secret === null || ! is_string($pairs) || $pairs === '' || strlen($pairs) > self::FONTS_MAX_LENGTH
            || preg_match('/^[0-9]{1,5}:[0-9]{1,5}(,[0-9]{1,5}:[0-9]{1,5})*$/', $pairs) !== 1) {
            return null;
        }

        $tokens = [];
        foreach (array_unique(explode(',', $pairs)) as $pair) {
            $tokens[] = substr(self::keyed('fonts', $pair, $secret), 0, 8);
        }
        $tokens = array_values(array_unique($tokens));
        sort($tokens, SORT_STRING);

        return implode(',', $tokens);
    }

    /**
     * Jaccard similarity of two `fonts` token lists, 0..1; null when either is empty.
     */
    public static function fontsSimilarity(string $a, string $b): ?float
    {
        $setA = array_filter(explode(',', $a), static fn (string $p): bool => $p !== '');
        $setB = array_filter(explode(',', $b), static fn (string $p): bool => $p !== '');

        if ($setA === [] || $setB === []) {
            return null;
        }

        $intersection = count(array_intersect($setA, $setB));
        $union = count(array_unique([...$setA, ...$setB]));

        return $union === 0 ? null : round($intersection / $union, 3);
    }

    /**
     * Hamming distance of two equal-length bit strings, or null when the lengths differ.
     */
    public static function bitsDistance(string $a, string $b): ?int
    {
        if (strlen($a) !== strlen($b)) {
            return null;
        }

        $distance = 0;
        for ($i = 0, $n = strlen($a); $i < $n; $i++) {
            if ($a[$i] !== $b[$i]) {
                $distance++;
            }
        }

        return $distance;
    }

    private static function emoji(mixed $width): ?int
    {
        $px = self::int($width);

        return ($px !== null && $px > 0) ? intdiv($px, self::EMOJI_BUCKET) * self::EMOJI_BUCKET : null;
    }

    private static function bits(mixed $value): ?string
    {
        return (is_string($value) && preg_match('/^[01]{1,64}$/', $value) === 1) ? $value : null;
    }

    /**
     * WebGPU `vendor/architecture` when the browser exposes it (the same across engines by
     * spec), else a keyed hash of the engine-conditioned WebGL tuple.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private static function gpu(array $claims, ?string $engine, ?string $secret): ?string
    {
        $vendor = EnvironmentConsistency::read($claims, 'tier2', 'gpu', 'webgpu', 'vendor');
        if (is_string($vendor) && trim($vendor) !== '') {
            $architecture = EnvironmentConsistency::read($claims, 'tier2', 'gpu', 'webgpu', 'architecture');
            $architecture = is_string($architecture) ? trim(strtolower($architecture)) : '';

            return 'webgpu:'.trim(strtolower($vendor)).'/'.$architecture;
        }

        $webgl = EnvironmentConsistency::read($claims, 'tier2', 'gpu', 'webgl');
        if (! is_array($webgl) || $secret === null) {
            return null;
        }

        // `precision` is `{frag: 'min,max,prec', vert: 'min,max,prec'}` (client v3).
        $precision = $webgl['precision'] ?? null;
        if (is_array($precision)) {
            $frag = $precision['frag'] ?? null;
            $vert = $precision['vert'] ?? null;
            $precision = (is_string($frag) && is_string($vert)) ? $frag.'/'.$vert : null;
        }
        $limits = $webgl['limits'] ?? null;
        if (! is_string($precision) || ! is_array($limits) || $limits === []) {
            return null;
        }

        ksort($limits);
        $tuple = [];
        foreach ($limits as $name => $limit) {
            if (is_string($name) && is_scalar($limit)) {
                $tuple[] = $name.'='.$limit;
            }
        }

        // Engine-conditioned: the limits are ANGLE/engine caps, not GPU caps, so the class
        // is prefixed with the engine and two engines' classes are incomparable (neutral
        // in the matcher) rather than a disagreement on every browser switch.
        return 'webgl:'.($engine ?? 'unknown').':'.self::keyed('gpu', ($engine ?? 'unknown').'|'.$precision.'|'.implode(',', $tuple), $secret);
    }

    /**
     * The OS voice set as `keyed(osHash):osCount`. An EMPTY set is absent, not a value:
     * "voices not loaded within 300 ms", "no speech backend" and "Linux without voices"
     * would otherwise all agree on one constant with weight 2 (round-2 BR2-4 / STD-26 /
     * BE2-11). The client's 32-bit fnv1a hash is keyed server-side so the stored value
     * is deployment-bound (SEC2-3); null without a secret.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private static function voices(array $claims, ?string $secret): ?string
    {
        $hash = EnvironmentConsistency::read($claims, 'tier2', 'voices', 'osHash');
        $count = self::int(EnvironmentConsistency::read($claims, 'tier2', 'voices', 'osCount'));

        if ($secret === null || ! is_string($hash) || preg_match('/^[0-9a-f]{1,16}$/i', $hash) !== 1 || $count === null || $count < 1) {
            return null;
        }

        return self::keyed('voices', strtolower($hash), $secret).':'.$count;
    }

    /**
     * @param  array<array-key, mixed>  $claims
     */
    private static function decoders(array $claims): ?string
    {
        $parts = [];
        foreach (['h264', 'vp9', 'av1'] as $codec) {
            $bits = EnvironmentConsistency::read($claims, 'tier2', 'decoders', $codec);
            if (! is_string($bits) || preg_match('/^[01]{3}$/', $bits) !== 1) {
                return null;
            }
            $parts[] = $bits;
        }

        return implode('|', $parts);
    }

    private static function memory(mixed $value): ?string
    {
        if (! is_int($value) && ! is_float($value)) {
            return null;
        }

        if ($value <= 0 || $value > 64) {
            return null;
        }

        // 0.25, 0.5, 1 .. 8 per spec; rendered without a trailing `.0`.
        return rtrim(rtrim(number_format((float) $value, 2, '.', ''), '0'), '.');
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * @param  array<array-key, mixed>  $claims
     */
    private static function userAgent(array $claims, TransportIntegrityResult $transport): ?string
    {
        $claimed = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'userAgent');
        if (is_string($claimed) && $claimed !== '') {
            return $claimed;
        }

        return $transport->witnessString('user_agent');
    }

    private static function int(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_float($value) && floor($value) === $value && abs($value) < PHP_INT_MAX) {
            return (int) $value;
        }

        return null;
    }

    /**
     * First 16 hex of an HMAC-SHA256 under the scoped secret, domain-separated per component.
     */
    private static function keyed(string $component, string $value, string $secret): string
    {
        return substr(hash_hmac('sha256', $component."\0".$value, $secret), 0, 16);
    }
}

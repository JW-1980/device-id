<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint;

/**
 * Every measurement METHOD the browser collector can run, with whether an operator may
 * switch it off.
 *
 * ## Why methods are switchable at all
 *
 * The weights in {@see CheckRegistry} switch RULES off: a rule silenced scores nothing, but
 * the probe it reads still runs in every visitor's browser. That is the wrong lever for two
 * questions an operator has to be able to answer without a deploy:
 *
 * 1. **Does this method pay for itself?** A probe costs milliseconds on every sign-in and
 *    bytes on every envelope. The only honest way to know what it buys is to run the same
 *    traffic with it on and with it off and compare the match rate, the false-positive rate
 *    and the collection cost — which needs the method itself to be switchable, not its rule.
 * 2. **Does this method hurt real users?** A probe that raises a permission prompt in one
 *    browser (canvas reads under Firefox resistFingerprinting, notes/19 C2), or that is slow
 *    on one class of device, has to be stoppable in minutes.
 *
 * ## Core methods cannot be switched off, and the reason is the device keys
 *
 * `browser_key` is an HMAC over the stabilised tier-1 claims and `hardware_key` over seven
 * hardware components. Removing any probe that feeds either changes the input and therefore
 * the key of EVERY device on the next visit — a one-time re-key of the whole population
 * disguised as a configuration change. So the probes that feed a key, and the two integrity
 * probes the design calls the most important in the system (integrity.ts), are `core` and the
 * admin screen renders them read-only. Everything else is a consistency input or a soft
 * matcher component, and losing one degrades the matcher's coverage, never its identity.
 *
 * ## The policy is published to the client and applied on the server
 *
 * The challenge response carries `disabled_probes`, the page carries the same list in a
 * `<meta name="nc-fingerprint-disabled">` for the identify path, and the collector skips the
 * named probes. The server reads the same list through {@see disabled()} so
 * `ConfidenceScorer` does not count a switched-off probe as missing — otherwise every
 * operator experiment would show up as a coverage drop.
 *
 * Names are the client's probe names (value-probes.ts `VALUE_PROBES[].name`, integrity.ts
 * probe names), spelled identically; the collector matches on the string.
 */
final class ProbeRegistry
{
    public const TIER_INTEGRITY = 'integrity';

    public const TIER_ONE = 'tier1';

    public const TIER_TWO = 'tier2';

    public const TIER_HARDWARE = 'hardware';

    /**
     * name => [tier, core, family, description]
     *
     * @var array<string, array{string, bool, string, string}>
     */
    private const METHODS = [
        // --- Integrity: does the environment look tampered with? ----------------------
        'wrongReceiver' => [self::TIER_INTEGRITY, true, 'integrity', 'Calls WebIDL attribute getters with the wrong receiver; a real getter throws, a patched closure does not. The highest-yield tamper probe (6/6 measured).'],
        'descriptorIntegrity' => [self::TIER_INTEGRITY, true, 'integrity', 'Checks that thirty navigator attributes still have native, stable, setter-less descriptors on the prototype and no own-property shadow on the instance.'],
        'mathDual' => [self::TIER_INTEGRITY, false, 'integrity', 'Computes transcendental functions two independent ways; a lookup-table spoofer cannot make both agree.'],
        'canvasDual' => [self::TIER_INTEGRITY, false, 'integrity', 'Rasterises the same shape two ways and tests the fill-rule distinction; a stub canvas diverges.'],
        'domBlockers' => [self::TIER_INTEGRITY, false, 'integrity', 'Reads automation and extension footprints (driver globals, chrome.runtime, getEventListeners) and whether navigator.webdriver was deleted.'],
        'canvasFill' => [self::TIER_INTEGRITY, false, 'integrity', 'A solid fill read back pixel by pixel; any deviation is read-side noise (farbling or a noise extension), so canvas values cannot identify the device.'],
        'lieBattery' => [self::TIER_INTEGRITY, false, 'integrity', 'Native-function invariants (not constructible, own keys exactly length and name, native source, cyclic-prototype TypeError) on ~25 fingerprinting-relevant functions; a Proxy or closure fails several.'],
        'phantomRealm' => [self::TIER_INTEGRITY, false, 'integrity', 'A transient same-origin iframe: a pristine Function.prototype.toString applied to page functions, DOMRect and SVG text arithmetic, CSS-path screen size, and the OS system fonts and colours.'],
        // Core since the five-review round: it gates DeviceComponents::untrusted(), the
        // per-component trust projection. Switched off, a component measured under
        // Brave/RFP/Tor would silently count as identity.
        'resistance' => [self::TIER_INTEGRITY, true, 'integrity', 'Detects Brave, Firefox resistFingerprinting and Tor Browser (timer granularity, missing APIs) so their noised components are not trusted as device identity. Never a finding.'],

        // --- Tier 1: synchronous, every load -------------------------------------------
        'environment' => [self::TIER_ONE, true, 'identity', 'Screen, viewport and the navigator identity fields a spoofer must fabricate. The core of browser_key.'],
        'uaClientHints' => [self::TIER_ONE, true, 'identity', 'User-Agent Client Hints as the page sees them, compared with the Sec-CH-UA headers the browser sent.'],
        'dateParsing' => [self::TIER_ONE, true, 'engine', 'The Date fallback parser across 23 inputs; the highest-value engine signal measured.'],
        'codecs' => [self::TIER_ONE, true, 'engine', 'canPlayType over 17 MIME types; container support per build.'],
        'esFeatures' => [self::TIER_ONE, true, 'engine', '77 ECMAScript and web feature detections; compared with the claimed browser version through the MDN ship table.'],
        'objectShape' => [self::TIER_ONE, true, 'engine', 'Own-property counts of Navigator, Document and Screen prototypes.'],
        'removedApiBoundary' => [self::TIER_ONE, true, 'engine', 'Which removed or prefixed APIs still exist; the complement of the feature list.'],
        'cssMedia' => [self::TIER_ONE, true, 'device', '24 media-query outcomes; feeds the display component of hardware_key.'],
        'architecture' => [self::TIER_ONE, true, 'device', 'CPU architecture from the sign of the default NaN; x86 against ARM.'],
        // Core since round 4 (security review F4): it is the evidence the privacy-mode gate
        // (`resistance`, itself core) needs. Switched off, every honest Firefox
        // resistFingerprinting / Tor Browser visitor lost its protection and was linked to
        // the whole cohort by its shared browser key again — "block one, block all".
        'engineIdentity' => [self::TIER_ONE, true, 'engine', 'Which JavaScript engine the runtime IS (error-object shape, stack format), compared with the engine the User-Agent names. Also the evidence that lets a privacy-mode report (resistance) be honoured, so it is always collected.'],

        // --- Tier 2: deferred to idle time --------------------------------------------
        'textMetrics' => [self::TIER_TWO, false, 'engine', 'TextMetrics field set and sub-pixel widths; a browser-version oracle.'],
        'errorText' => [self::TIER_TWO, false, 'engine', 'Exact engine error strings.'],
        'audioRealtime' => [self::TIER_TWO, true, 'device', 'AudioContext sample rate, channels and latency; the audio component the matcher scores.'],
        'permissions' => [self::TIER_TWO, false, 'environment', 'Permission states for 18 registry names plus Notification.permission; the headless pair is a rule input.'],
        'canvasGeometry' => [self::TIER_TWO, false, 'device', 'A pixel hash of drawn geometry; random under canvas noise, so a weak signal.'],
        'fontFallback' => [self::TIER_TWO, false, 'engine', 'Which generic families collide by measured width.'],
        'intl' => [self::TIER_TWO, false, 'environment', 'Resolved locale and time zone; compared with Accept-Language and the language list.'],
        'audioOffline' => [self::TIER_TWO, false, 'engine', 'OfflineAudioContext render sum; an engine constant.'],
        'heapMemory' => [self::TIER_TWO, false, 'device', 'measureUserAgentSpecificMemory; cross-origin-isolated pages only.'],
        'buildFingerprint' => [self::TIER_TWO, false, 'engine', 'ICU and tzdata build sizes (currency count 159 against 307); a build fact, not a preference.'],
        'workerScope' => [self::TIER_TWO, false, 'integrity', 'The same navigator, Intl and WebGL facts read inside a dedicated worker, a realm page-level spoofers do not reach, compared with the page.'],
        'audioReadback' => [self::TIER_TWO, false, 'integrity', 'A rendered constant, a rendered silence, an analyser on silence and a trap value, each of which must read back exactly; any deviation is audio noise.'],
        'timezoneLmt' => [self::TIER_TWO, false, 'environment', 'The engine\'s own 1113 local-mean-time offset against the Intl time zone\'s; an Intl-only time zone spoof disagrees.'],

        // --- Hardware tier: cross-browser device/OS signals ----------------------------
        'fontMetrics' => [self::TIER_HARDWARE, false, 'device', 'Installed fonts by measured width pairs; the fonts matcher component.'],
        'emojiMetrics' => [self::TIER_HARDWARE, false, 'device', 'Width of the system emoji font.'],
        'scripts' => [self::TIER_HARDWARE, false, 'device', 'Which writing systems the device can display.'],
        'gpu' => [self::TIER_HARDWARE, false, 'device', 'WebGPU adapter and WebGL renderer, limits and precision, plus WebGL1-against-WebGL2 parameter agreement.'],
        'audioHardware' => [self::TIER_HARDWARE, true, 'device', 'Sample rate, channel count and latency bucket; the audio component when the realtime context declines.'],
        'decoders' => [self::TIER_HARDWARE, false, 'device', 'Which video codecs decode smoothly and efficiently.'],
        'voices' => [self::TIER_HARDWARE, false, 'device', 'Speech voices that ship with the operating system.'],
        'fontFaces' => [self::TIER_HARDWARE, false, 'device', 'document.fonts.check over OS-indicative families; the OS the fonts imply is compared with the User-Agent.'],
        'parallelism' => [self::TIER_HARDWARE, false, 'device', 'Measured parallel capacity from timed workers, compared with the reported core count; a CDP or Brave override of hardwareConcurrency cannot change the measurement. Costs CPU; off by default.'],
        'keyboardLayout' => [self::TIER_HARDWARE, false, 'device', 'A hash of the physical keyboard layout map (Chromium desktop only).'],
        'gpuMath' => [self::TIER_HARDWARE, false, 'device', 'How the GPU rounds transcendental arithmetic in a shader, read back as pixels; the same across browsers on the same driver, so a cross-browser matcher component. Absent on software renderers.'],
        // --- Tier 2, merged in from the second host's collector (probe set 3) ---------
        // Neither feeds a key. `webrtc` moves with the browser build (a codec list changes at
        // a browser update), so it is no device fact; `behavior` is session data that differs
        // on every visit. `DeviceKeyDeriver` keeps the whole tier-2 block out of `browser_key`
        // and `DeviceComponents` has no component for either.
        'webrtc' => [self::TIER_TWO, false, 'engine', 'Audio and video codecs, RTCP feedback and RTP header extensions from a local WebRTC offer; no ICE gathering, no address. A browser-build signal, in no key.'],
        'behavior' => [self::TIER_TWO, false, 'environment', 'Passive aggregates of pointer, keyboard, wheel, touch and motion input on the page (counts, timing statistics, a hash of the physical key codes; no coordinates, no typed characters). Session data, in no key; unavailable when the visitor has not touched the page.'],
    ];

    /**
     * The probe set this registry describes: the number a collector bundle sends as `probes`
     * in its envelope (protocol.ts `PROBE_SET`). Bumped whenever a method is added, so the
     * omission gate expects of a client only the probes its bundle has
     * ({@see PROBE_SET_ADDED}); without that, an honest page left open across a deploy reads
     * as a client that dropped every probe added since.
     */
    public const PROBE_SET = 3;

    /**
     * The probe set a body WITHOUT a `probes` marker is judged against: the collector on
     * `main` before the marker existed (commit 36f07b75).
     */
    public const LEGACY_PROBE_SET = 1;

    /**
     * The probe set that introduced each method; every method not listed is in set 1.
     *
     * Set 1 is what the collector at 36f07b75 (`main` before the marker) sends: tier 1
     * dateParsing … architecture (10 probes), integrity wrongReceiver, descriptorIntegrity,
     * mathDual, canvasDual, domBlockers, and tier 2/hardware textMetrics … voices (17). Read
     * from that commit's value-probes.ts `VALUE_PROBES` and integrity.ts `collectIntegrity()`;
     * its deferred envelope carried no integrity data.
     *
     * @var array<string, int>
     */
    public const PROBE_SET_ADDED = [
        'engineIdentity' => 2,
        'canvasFill' => 2,
        'lieBattery' => 2,
        'phantomRealm' => 2,
        'resistance' => 2,
        'workerScope' => 2,
        'audioReadback' => 2,
        'timezoneLmt' => 2,
        'fontFaces' => 2,
        'parallelism' => 2,
        'keyboardLayout' => 2,
        'gpuMath' => 2,
        'webrtc' => 3,
        'behavior' => 3,
    ];

    /**
     * Methods switched off when the operator has never chosen: measured-parallelism costs
     * real CPU on every visit and is an experiment until measured; the keyboard layout has
     * no server consumer yet, and data nothing reads is not collected (CLAUDE.md, data
     * minimisation — security review).
     *
     * @var list<string>
     */
    public const DEFAULT_DISABLED = ['parallelism', 'keyboardLayout'];

    /**
     * Which method raises each client-side integrity finding, so a switched-off method's
     * findings can be dropped together with its data. A code that is not here belongs to a
     * server rule or to a core probe and is never dropped.
     *
     * @var array<string, string>
     */
    private const FINDING_PROBES = [
        'math_pf_mismatch' => 'mathDual',
        'canvas_dual_diverged' => 'canvasDual',
        'canvas_winding_false' => 'canvasDual',
        'dom_blocker_threw' => 'domBlockers',
        'dom_blocker_present' => 'domBlockers',
        'canvas_readback_perturbed' => 'canvasFill',
        'lie_battery_failed' => 'lieBattery',
        'realm_tostring_mismatch' => 'phantomRealm',
        'domrect_inconsistent' => 'phantomRealm',
        'svg_text_inconsistent' => 'phantomRealm',
    ];

    /**
     * The claim set without the data of switched-off methods.
     *
     * Switching a method off stops its COLLECTION, but a cached pre-policy bundle, or a
     * client that ignores the policy, still sends the data, and the rules read whatever
     * arrives. "Stoppable in minutes" has to hold for scoring as well as collection
     * (sceptical review), so the server drops a disabled method's tier-1/tier-2 value, its
     * integrity data and the findings it raises before anything reads them. Core names are
     * never in the list ({@see disabled()}), so a key input can never be stripped.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  list<string>  $disabled
     * @return array<array-key, mixed>
     */
    public static function stripDisabled(array $claims, array $disabled): array
    {
        // A container sent as `{state: 'ok', value: {…}}` is read through by every reader
        // (they unwrap a probe envelope at every path step), so diffing the wrapper's own
        // keys stripped nothing and a switched-off method's data reached the rules (security
        // review round 4, F3). Every container is reduced to what the readers see first;
        // for a plain container that is the identity, so honest bodies are unchanged.
        foreach (['tier1', 'tier2', 'integrity'] as $location) {
            if (array_key_exists($location, $claims)) {
                $claims[$location] = self::unwrapContainer($claims[$location]);
            }
        }
        if (is_array($claims['integrity'] ?? null) && array_key_exists('data', $claims['integrity'])) {
            $claims['integrity']['data'] = self::unwrapContainer($claims['integrity']['data']);
        }

        if ($disabled === []) {
            return $claims;
        }

        $off = array_fill_keys(array_filter($disabled, static fn (mixed $n): bool => is_string($n) && isset(self::METHODS[$n]) && ! self::METHODS[$n][1]), true);
        if ($off === []) {
            return $claims;
        }

        foreach (['tier1', 'tier2'] as $tier) {
            if (is_array($claims[$tier] ?? null)) {
                $claims[$tier] = array_diff_key($claims[$tier], $off);
            }
        }

        $integrity = $claims['integrity'] ?? null;
        if (is_array($integrity)) {
            if (is_array($integrity['data'] ?? null)) {
                $integrity['data'] = array_diff_key($integrity['data'], $off);
            }
            if (is_array($integrity['findings'] ?? null)) {
                $integrity['findings'] = array_values(array_filter($integrity['findings'], static function (mixed $finding) use ($off): bool {
                    $code = is_array($finding) && is_string($finding['code'] ?? null) ? $finding['code'] : null;
                    $probe = $code === null ? null : (self::FINDING_PROBES[$code] ?? null);

                    return $probe === null || ! isset($off[$probe]);
                }));
            }
            $claims['integrity'] = $integrity;
        }

        return $claims;
    }

    /**
     * A container as the readers see it: the `value` of a `{state, value}` probe envelope,
     * repeatedly (the readers unwrap at every step), else the node itself.
     */
    private static function unwrapContainer(mixed $node): mixed
    {
        while (is_array($node) && array_key_exists('state', $node) && array_key_exists('value', $node)) {
            $node = $node['value'];
        }

        return $node;
    }

    /**
     * The probe set a client reported, as the server applies it: an absent or malformed
     * marker is the legacy set, and a number above the newest set this registry knows is the
     * newest (the server can only expect probes it knows).
     */
    public static function probeSet(mixed $reported): int
    {
        if (! is_int($reported) || $reported < self::LEGACY_PROBE_SET) {
            return self::LEGACY_PROBE_SET;
        }

        return min($reported, self::PROBE_SET);
    }

    /**
     * Every method of a probe set with its tier and whether it is core: what the server
     * expects of a collector bundle of that set (`ProbeOmission`). Not {@see describe()},
     * which is the admin screen's view and also resolves the host policy.
     *
     * @return array<string, array{tier: string, core: bool}>
     */
    public static function methods(int $probeSet = self::PROBE_SET): array
    {
        $out = [];
        foreach (self::METHODS as $name => [$tier, $core]) {
            if ((self::PROBE_SET_ADDED[$name] ?? self::LEGACY_PROBE_SET) <= $probeSet) {
                $out[$name] = ['tier' => $tier, 'core' => $core];
            }
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    public static function names(): array
    {
        return array_keys(self::METHODS);
    }

    /**
     * @return list<string>
     */
    public static function toggleable(): array
    {
        return array_values(array_filter(self::names(), static fn (string $name): bool => ! self::METHODS[$name][1]));
    }

    /**
     * @return list<string>
     */
    public static function core(): array
    {
        return array_values(array_filter(self::names(), static fn (string $name): bool => self::METHODS[$name][1]));
    }

    public static function isCore(string $name): bool
    {
        return isset(self::METHODS[$name]) && self::METHODS[$name][1];
    }

    /**
     * The methods switched off under the host's settings: only known, non-core names.
     *
     * The host supplies `disabled_probes` as a list of names (the admin screen writes it).
     * A core name in the list is dropped rather than honoured, so no configuration can
     * re-key the device population; an unknown name is dropped so a stale list after a
     * probe is renamed silently does nothing rather than silently doing something else.
     *
     * @return list<string>
     */
    public static function disabled(Settings $settings = new Settings): array
    {
        $stored = $settings->get('disabled_probes');
        if (! is_array($stored)) {
            return self::DEFAULT_DISABLED;
        }

        $out = [];
        foreach ($stored as $name) {
            if (is_string($name) && isset(self::METHODS[$name]) && ! self::METHODS[$name][1]) {
                $out[] = $name;
            }
        }

        return array_values(array_unique($out));
    }

    /**
     * What the admin screen renders: every method with its tier, family, description, and
     * whether it is currently collecting.
     *
     * @return array<string, array{tier: string, core: bool, family: string, description: string, enabled: bool}>
     */
    public static function describe(Settings $settings = new Settings): array
    {
        $disabled = array_fill_keys(self::disabled($settings), true);

        $out = [];
        foreach (self::METHODS as $name => [$tier, $core, $family, $description]) {
            $out[$name] = [
                'tier' => $tier,
                'core' => $core,
                'family' => $family,
                'description' => $description,
                'enabled' => $core || ! isset($disabled[$name]),
            ];
        }

        return $out;
    }
}

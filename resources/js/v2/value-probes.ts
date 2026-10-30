/**
 * Value probes: properties of the environment, used for identification only.
 *
 * ## Read this before adding a probe
 *
 * **A value probe cannot detect an attacker.** Measured across 3 engines and 2
 * configurations, 0 of 162 value-probe runs detected a stealth spoofer, and 0 were
 * classified as "collapsed" — a competent spoofer substitutes a *plausible* value
 * rather than an impossible one, so nothing about the value itself gives it away.
 *
 * A value probe's only job is to contribute to a cross-check the server makes
 * against something the transport already proved (`Sec-CH-UA-Platform`, the
 * User-Agent it claimed, its own language list). Put a new probe here only if the
 * server has a rule that uses it. A probe nothing consumes is bytes on every
 * request.
 *
 * ## Three of them currently break that rule, deliberately
 *
 * `buildFingerprint`, `objectShape` and `removedApiBoundary` have no server rule and no
 * `ConfidenceScorer::WEIGHTS` entry, so they cost a little on every load and currently buy
 * nothing the server reads. They are here because they were MEASURED (notes/15) and because
 * the alternative — leaving them in a research harness — means the values are not in the
 * claim set when the rules that need them get written. That is a deliberate trade and it is
 * the first thing to revisit.
 *
 * ## Adding a probe here RE-KEYS EVERY EXISTING DEVICE
 *
 * `DeviceKeyDeriver::derive()` hashes the whole stabilised claim set, and `presenceVector()`
 * hashes the sorted set of probe names that returned a value. Three new tier-1 probes change
 * both, for every device, on deploy. That is a one-time event rather than a regression, but
 * the stability is not automatic and nothing warns about it, so it is written here. The
 * mitigation when a re-key is unacceptable is the volatility measurement in notes/15 §A.
 *
 * ## Every probe here was measured
 *
 * Numbers are from research/fingerprinting: 3 engines x 4 configurations x 2
 * reloads = 24 cells, 3 in-page repeats. `value` is normalised entropy x
 * cross-load-stability / (median cost + 0.5 ms). Anything scoring 0.000 was
 * **falsified and is not here** — the RegExp feature matrix, JSON/structuredClone
 * edge cases, TypedArray semantics including the Float32 NaN payload, Map/Set
 * ordering and async interleaving were all byte-identical across the three engines.
 * The lesson those five failures produced is in REPORT.md section 7.25:
 *
 *   A signature is only stable if the specification makes it stable.
 *
 * Every probe below reads behaviour the specification leaves *unspecified*, which is
 * why they still differ between engines: rasterisation, font metrics, audio mixing,
 * ICU data, error-message text, and the `Date` fallback parser.
 *
 * ## Budget
 *
 * Tier 1 must total under 5 ms and runs synchronously. That one is asserted in
 * tests/Browser/transport-checks.mjs, and it holds with room to spare.
 *
 * Tier 2 used to say "must total under 25 ms" here, and nothing checked it. It now reads
 * the measured reality, because the old sentence was the kind of thing that reads as a
 * constraint while being a comment:
 *
 *     chromium  89.4 ms    firefox  158.0 ms    webkit  37.0 ms
 *
 * That is 1.5x to 6.3x over, and `canvasGeometry` alone was measured at 129 ms in Firefox
 * against 5 ms in WebKit — a 26x spread on one probe, one machine. Those figures are the
 * SUM OF A SEQUENTIAL DIAGNOSTIC (`measureProbes()` runs in sequence by design, so each row
 * localises an overrun). Production runs a tier through `Promise.all`, so the wall time is
 * lower — but the sum is what is ratcheted, and it is a bound on the work, not a prediction
 * of the elapsed time. notes/15 has the measurement and the reasoning.
 *
 * The right fix is not raising the number: tier 2 runs in `requestIdleCallback` and a
 * quarter of a second of work in one idle slice will jank a page however idle it was. It is
 * chunking tier 2 across several idle callbacks, which is a design change and is not made
 * here. WebGPU remains recorded and not built; the WebGL probe is already in tier 2 and
 * shares the un-chunked idle slice, so measure before adding another expensive probe.
 *
 * `voices` is the exception that proves the rule: it can wait up to 300 ms for
 * `voiceschanged`, but that is WAIT, not work, and it runs in idle time. The CPU sum above
 * is unchanged by it; the idle callback's 3 s timeout is the bound that matters.
 *
 * The whole-collection 30 ms budget (`BUDGET_MS`) is tier 1 and is asserted. An earlier
 * revision of the timer probe cost 65.7 ms on its own for a single signal, and nothing but
 * measurement would have caught it.
 */

import {
    failed,
    fnv1a32,
    ok,
    probe,
    probeAsync,
    unavailable,
    type ProbeResult,
} from './canonical';
import { behavior } from './behavior';
import {
    hasMember,
    type LooseIntlOptions,
    type NavigatorWithUserAgentData,
    type ScreenWithAvail,
    type Uint8ArrayWithBase64,
} from './types';

export const TIER = { ONE: 1, TWO: 2 } as const;
export type Tier = (typeof TIER)[keyof typeof TIER];

// =====================================================================
// TIER 1 - cheap, synchronous
// =====================================================================

/**
 * Frames in a caught error's stack, or -1 when there is no stack.
 *
 * `error.stack` is typed `string | undefined` and is genuinely absent for some
 * error types in some engines, so every read is guarded. Centralised so
 * `stackDepth` does not repeat the same conditional three times.
 */
function stackLineCount(error: unknown): number {
    const stack = error instanceof Error ? error.stack : undefined;

    return typeof stack === 'string' ? stack.split('\n').length : -1;
}

function stackLine(error: unknown, index: number): string | undefined {
    const stack = error instanceof Error ? error.stack : undefined;
    if (typeof stack !== 'string') return undefined;

    return stack.split('\n')[index];
}

/**
 * The `Date` string-parser fallback matrix. **The highest-value value probe
 * measured**, and it is not close among the new ones.
 *
 * Measured: 6 classes, normalised entropy 0.527, in-page and cross-load stability
 * both 1.00, 0.020 ms, value score 1014 — third best in the whole catalogue,
 * beating both `intl` and `canvas_text` while costing a hundredth of the latter.
 *
 * Why it works: `new Date(string)` routes through a spec-defined *fallback* parser
 * whose accepted forms are implementation-defined. The ISO-8601 fast path is
 * specified, so it never differs; the fallback does. That is the same reason the
 * falsified probes failed, inverted, and it is why the technique generalises:
 * **look for unspecified behaviour, not specified behaviour.**
 *
 * And it is tamper-proof in the useful sense: the test spoofer did not touch it
 * (UNCHANGED 6/6), and patching it would mean reimplementing a date parser. It
 * identifies an *engine*, never a *device*, so it carries no cross-device tracking
 * risk at all — which makes it an unusually cheap signal to ship.
 */
export function dateParsing(): ProbeResult<Record<string, string>> {
    return probe('dateParsing', () => {
        const inputs = [
            '2024-01-15', '2024-01-15T10:20:30', '2024-01-15T10:20:30Z',
            '2024-01-15T10:20:30.123Z', '2024-01-15 10:20:30', '2024-01-15T10:20',
            '2024-01-15T10:20:30+05:30', '2024-01-15T10:20:30-08',
            'Mon, 15 Jan 2024 10:20:30 GMT', 'January 15, 2024', '15 January 2024',
            '2024/01/15', '01/15/2024', '2024-13-45', '2024-02-30T00:00:00Z',
            'T10:20', '10:20', 'Jan 15 2024', '20240115', '2024-W03-1',
            'not a date', '', '2024-01-15T10:20:30.123456789Z',
        ];

        const out: Record<string, string> = {};
        for (const input of inputs) {
            const date = new Date(input);
            out[input] = Number.isNaN(date.getTime()) ? 'NaN' : date.toISOString();
        }

        return out;
    });
}

/**
 * CSS media-query state vector. 0.040 ms, 3 classes, value score 605.9.
 *
 * These are *user settings*, not engine constants: reduced-motion, colour scheme,
 * contrast preference, colour gamut, forced colours, dynamic range. That matters —
 * they separate **devices** rather than builds, and identifying a device is the
 * job. The `reproduce()` form is used so the server can ask for the same query it
 * is checking, which keeps the check in one place instead of two.
 */
export function cssMedia(): ProbeResult<string> {
    return probe('cssMedia', () => {
        const queries = [
            '(prefers-reduced-motion: reduce)', '(prefers-color-scheme: dark)',
            '(prefers-contrast: more)', '(prefers-contrast: less)', '(forced-colors: active)',
            '(any-hover: hover)', '(any-pointer: coarse)', '(pointer: fine)', '(hover: hover)',
            '(display-mode: browser)', '(inverted-colors: inverted)', '(dynamic-range: high)',
            '(video-dynamic-range: high)', '(color-gamut: srgb)', '(color-gamut: p3)',
            '(color-gamut: rec2020)', '(scripting: enabled)', '(update: fast)', '(monochrome)',
            '(prefers-reduced-data: reduce)', '(prefers-reduced-transparency: reduce)',
            '(prefers-contrast: custom)', '(pointer: coarse)', '(hover: none)',
        ];

        return queries
            .map((query) => {
                try {
                    return matchMedia(query).matches ? '1' : '0';
                } catch {
                    return 'x';
                }
            })
            .join('');
    });
}

/**
 * A 79-entry feature-presence matrix over ES2022..ES2026 and current web APIs.
 * 0.160 ms, 3 classes, value score 523.8.
 *
 * Its value is not discrimination between current engines — that is only 3 classes
 * because all three are on a similar release cadence. Its value is as a **version
 * cross-check**: it detects a client claiming to be an old browser while behaving
 * like a new one, and it pairs with `Sec-CH-UA-Full-Version-List` to give two
 * independent version claims. A spoofer would have to know this exact list.
 *
 * Entries are `1` (present), `0` (absent) or `-1` (the probe threw). Only the names
 * of the PRESENT features are returned, because that is the compact form and the
 * absent set is implied by the version.
 */
export function esFeatures(): ProbeResult<{ count: number; present: string }> {
    return probe('esFeatures', () => {
        const has = (target: object, key: string): number => {
            try {
                return key in target ? 1 : 0;
            } catch {
                return -1;
            }
        };
        const tryBool = (fn: () => boolean): number => {
            try {
                return fn() ? 1 : 0;
            } catch {
                return 0;
            }
        };
        const global = globalThis as unknown as Record<string, unknown>;

        const checks: Record<string, number> = {
            // ES2022
            arrayAt: has(Array.prototype, 'at'),
            errorCause: has(Error.prototype, 'cause'),
            errorErrors: has(Error.prototype, 'errors'),
            regExpHasIndices: has(RegExp.prototype, 'hasIndices'),
            // ES2023
            arrayToSorted: has(Array.prototype, 'toSorted'),
            arrayToReversed: has(Array.prototype, 'toReversed'),
            arrayToSpliced: has(Array.prototype, 'toSpliced'),
            arrayWith: has(Array.prototype, 'with'),
            arrayFindLast: has(Array.prototype, 'findLast'),
            arrayFindLastIndex: has(Array.prototype, 'findLastIndex'),
            objectGroupBy: has(Object, 'groupBy'),
            structuredClone: has(global, 'structuredClone'),
            weakRef: has(global, 'WeakRef'),
            finalizationRegistry: has(global, 'FinalizationRegistry'),
            // ES2024
            promiseWithResolvers: has(Promise, 'withResolvers'),
            arrayBufferResize: has(ArrayBuffer.prototype, 'resize'),
            arrayBufferTransfer: has(ArrayBuffer.prototype, 'transfer'),
            arrayFromAsync: has(Array, 'fromAsync'),
            regexpVFlag: tryBool(() => {
                new RegExp('a', 'v');
                return true;
            }),
            stringIsWellFormed: has(String.prototype, 'isWellFormed'),
            stringToWellFormed: has(String.prototype, 'toWellFormed'),
            // ES2025
            iteratorHelpers: has((global.Iterator as { prototype?: object } | undefined)?.prototype ?? {}, 'map'),
            setUnion: has(Set.prototype, 'union'),
            mapGetOrInsert: has(Map.prototype, 'getOrInsert'),
            regexpEscape: has(RegExp, 'escape'),
            promiseTry: has(Promise, 'try'),
            // ES2026 candidates
            float16Array: tryBool(() => {
                new Float16Array(1);
                return true;
            }),
            uint8FromBase64: tryBool(() => typeof hasMember(Uint8Array as unknown as Uint8ArrayWithBase64, 'fromBase64') === 'function'),
            uint8ToBase64: tryBool(() => typeof hasMember(Uint8Array.prototype as unknown as Uint8ArrayWithBase64, 'toBase64') === 'function'),
            uint8SetFromBase64: tryBool(() => typeof hasMember(Uint8Array.prototype as unknown as Uint8ArrayWithBase64, 'setFromBase64') === 'function'),
            uint8ToHex: tryBool(() => typeof hasMember(Uint8Array.prototype as unknown as Uint8ArrayWithBase64, 'toHex') === 'function'),
            temporal: tryBool(() => typeof global.Temporal === 'object'),
            disposableStack: tryBool(() => typeof global.DisposableStack === 'function'),
            errorIsError: tryBool(() => typeof (Error as { isError?: unknown }).isError === 'function'),
            mathSumPrecise: tryBool(() => typeof (Math as { sumPrecise?: unknown }).sumPrecise === 'function'),
            // Web APIs
            schedulerYield: tryBool(() => typeof (global.scheduler as { yield?: unknown } | undefined)?.yield === 'function'),
            navLocks: tryBool(() => 'locks' in navigator),
            navCredentials: tryBool(() => 'credentials' in navigator),
            navMediaCapabilities: tryBool(() => 'mediaCapabilities' in navigator),
            navUsb: tryBool(() => 'usb' in navigator),
            navSerial: tryBool(() => 'serial' in navigator),
            navHid: tryBool(() => 'hid' in navigator),
            navBluetooth: tryBool(() => 'bluetooth' in navigator),
            navKeyboardLayout: tryBool(() => 'keyboard' in navigator),
            navModelId: tryBool(() => 'modelId' in navigator),
            navBattery: tryBool(() => 'getBattery' in navigator),
            navGamepads: tryBool(() => 'getGamepads' in navigator),
            viewTransitions: tryBool(() => typeof (document as Document & { startViewTransition?: unknown }).startViewTransition === 'function'),
            invokerCommands: tryBool(() => 'command' in HTMLElement.prototype),
            selectedContent: tryBool(() => 'selectedContent' in HTMLElement.prototype),
            trustedTypes: tryBool(() => typeof global.trustedTypes === 'object'),
            speechRecognition: tryBool(() => 'SpeechRecognition' in global || 'webkitSpeechRecognition' in global),
            offscreenCanvas: tryBool(() => typeof global.OffscreenCanvas === 'function'),
            imageDecoder: tryBool(() => typeof global.ImageDecoder === 'function'),
            videoFrame: tryBool(() => typeof global.VideoFrame === 'function'),
            webgpu: tryBool(() => 'gpu' in navigator),
            eyeDropper: tryBool(() => 'EyeDropper' in global),
            fileSystemPicker: tryBool(() => 'showOpenFilePicker' in global),
            wakeLock: tryBool(() => 'wakeLock' in navigator),
            showModalDialog: tryBool(() => typeof HTMLDialogElement.prototype.showModal === 'function'),
            popoverApi: tryBool(() => 'popover' in HTMLElement.prototype),
            // CSS
            cssHas: tryBool(() => CSS.supports('selector(:has(a))')),
            cssNesting: tryBool(() => CSS.supports('selector(&)')),
            cssSubgrid: tryBool(() => CSS.supports('grid-template-columns: subgrid')),
            cssOklch: tryBool(() => CSS.supports('color: oklch(50% 0.1 200)')),
            cssColorMix: tryBool(() => CSS.supports('color: color-mix(in oklch, red, blue)')),
            cssAnchor: tryBool(() => CSS.supports('anchor-name: --a')),
            cssScrollTimeline: tryBool(() => CSS.supports('animation-timeline: scroll()')),
            cssFieldSizing: tryBool(() => CSS.supports('field-sizing: content')),
            cssAttrTyped: tryBool(() => CSS.supports('width: attr(width type(<length>))')),
            cssTextWrapBalance: tryBool(() => CSS.supports('text-wrap: balance')),
            cssScrollbarGutter: tryBool(() => CSS.supports('scrollbar-gutter: stable')),
            cssInterpolateSize: tryBool(() => CSS.supports('interpolate-size: allow-keywords')),
            cssLinearEasing: tryBool(() => CSS.supports('transition-timing-function: linear(0, 1)')),
            cssStartingStyle: tryBool(() => CSS.supports('transition-behavior: allow-discrete')),
            cssLightDark: tryBool(() => CSS.supports('color: light-dark(red, blue)')),
            cssBackdropFilter: tryBool(() => CSS.supports('backdrop-filter: blur(2px)')),
            webkitAppearance: tryBool(() => 'webkitAppearance' in document.body.style),
        };

        const present = Object.keys(checks).filter((key) => checks[key] === 1);

        return { count: present.length, present: present.join(',') };
    });
}

/**
 * `TextMetrics` field set plus subpixel-positioning measurements.
 * 0.140 ms, 4 classes, value score 653.8.
 *
 * Which optional `TextMetrics` members exist is a per-engine constant, and the
 * fractional-size widths are a *rendering generation* index: subpixel text
 * positioning changed in Chrome 99 and Safari 17. That makes this a browser-version
 * oracle independent of the User-Agent string, which pairs with
 * `Sec-CH-UA-Full-Version-List` to give two version claims to compare.
 */
export function textMetrics(): ProbeResult<Record<string, unknown>> {
    return probe('textMetrics', () => {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        if (!context) throw new Error('no 2d context');

        context.font = '72px serif';
        const metrics = context.measureText('MHxg');

        const optional = [
            'actualBoundingBoxLeft', 'actualBoundingBoxRight', 'actualBoundingBoxAscent',
            'actualBoundingBoxDescent', 'fontBoundingBoxAscent', 'fontBoundingBoxDescent',
            'emHeightAscent', 'emHeightDescent', 'alphabeticBaseline', 'ideographicBaseline',
            'hangingBaseline',
        ];
        const present = optional.filter((key) => key in metrics);

        const fractional: Record<string, number> = {};
        for (const size of ['16.5px serif', '16.6667px serif', '17.2px serif']) {
            context.font = size;
            fractional[size] = Math.round(context.measureText('MWHjgq@#').width * 1e5) / 1e5;
        }

        // Ratios, not absolutes. A font install shifts the absolute widths for the
        // affected family only, so the relationship between families is far more
        // stable than either number - the standardisation-resistance idea from
        // REPORT.md 7.13, which also makes the value engine-invariant.
        const width = (family: string): number => {
            context.font = `72px ${family}`;
            return Math.round(context.measureText('mmMwWLliI0Oo').width * 1e4) / 1e4;
        };
        const ratios = {
            arialOverMono: Math.round((width('"Arial"') / width('monospace')) * 1e6) / 1e6,
            timesOverSerif: Math.round((width('"Times New Roman"') / width('serif')) * 1e6) / 1e6,
            courierOverMono: Math.round((width('"Courier New"') / width('monospace')) * 1e6) / 1e6,
        };

        let letterSpacing: string = 'unsupported';
        try {
            context.letterSpacing = '2px';
            letterSpacing = String(Math.round(context.measureText('abc').width * 1e3) / 1e3);
            context.letterSpacing = '0px';
        } catch { /* an engine without the property is the answer */ }

        return {
            presentCount: present.length,
            present: present.join(','),
            fractional,
            ratios,
            letterSpacing,
        };
    });
}

/**
 * Engine-specific error MESSAGE text. 0.295 ms, 4 classes, value score 509.1.
 *
 * The message half of this technique works and is included. The numeric and
 * serialisation edge cases that shared a draft of it were measured and are NOT
 * here: `structuredClone`, `JSON.parse`'s reviver `context` argument and the
 * `Float32Array` NaN payload are all byte-identical across the three engines. The
 * messages are not, because their wording is unspecified.
 */
export function errorText(): ProbeResult<Record<string, string>> {
    return probe('errorText', () => {
        const capture = (fn: () => unknown): string => {
            try {
                fn();
                return 'none';
            } catch (error) {
                const name = error instanceof Error ? error.name : 'Error';
                const message = error instanceof Error ? error.message : String(error);
                return `${name}|${message.slice(0, 70)}`;
            }
        };

        return {
            wasmCompile: capture(() => new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 255, 255, 255, 255]))),
            intlCurrency: capture(() => new Intl.NumberFormat('en', { style: 'currency', currency: 'XX' }).format(1)),
            intlFractionDigits: capture(() => new Intl.NumberFormat('en', { style: 'currency', currency: 'EUR', minimumFractionDigits: 99 })),
            intlCalendar: capture(() => new Intl.DateTimeFormat('en', { calendar: 'nope' } as LooseIntlOptions)),
            intlLocale: capture(() => new Intl.Locale('!!')),
            // The cast goes through `unknown` on purpose: `granularity` is
            // deliberately invalid, and the point of the probe is to read the
            // resulting RangeError message.
            segmenterGranularity: capture(
                () => new Intl.Segmenter('en', { granularity: 'nope' } as unknown as Intl.SegmenterOptions),
            ),
            dateToISOString: capture(() => new Date(8.64e15 + 1).toISOString()),
            dateInvalid: capture(() => new Date(NaN).toISOString()),
            toFixedRange: capture(() => (1.5).toFixed(101)),
            toPrecision: capture(() => (1.5).toPrecision(0)),
            regexpBadFlags: capture(() => new RegExp('a', 'q')),
            regexpDuplicateGroup: capture(() => new RegExp('(?<a>x)(?<a>y)')),
            decodeURI: capture(() => decodeURIComponent('%')),
            proxyRevoked: capture(() => {
                const revocable = Proxy.revocable({ a: 1 }, {}) as { proxy: object; revoke: () => void };
                revocable.revoke();
                return Object.keys(revocable.proxy).join(',');
            }),
            nullProtoToString: capture(() => Object.create(null).toString()),
            // A synchronous WebCrypto failure, for the engine-specific message. An
            // invalid `encrypt` algorithm would need a real CryptoKey to reach the
            // algorithm check, and passing a dummy one produces a *type* error about
            // the key instead - which is a WebIDL message, not a WebCrypto one, and
            // therefore not the signal. `getRandomValues` with a non-integer-typed
            // array throws synchronously, with the engine's own wording.
            cryptoBadTypedArray: capture(
                () => crypto.getRandomValues(new Float32Array(1) as unknown as ArrayBufferView<ArrayBuffer>),
            ),
        };
    });
}

/**
 * Call-stack depth at probe time. 0.050 ms, 4 classes, value score 735.8 —
 * sixth best in the whole catalogue.
 *
 * The frame count is a property of *how the probe was invoked*, not of the device. A
 * legitimate collector called from one place has a stable depth; a bot framework
 * that invokes it from inside a promise chain, a `setTimeout` or an eval wrapper has
 * a different one, and a spoofer cannot control what depth YOUR code produces.
 *
 * **Bucket it.** Measured in-page agreement is only 0.78, because `error.stack`
 * length varies with the frames actually captured. The raw number must never be
 * hashed; the server rounds it to a small range.
 */
export function stackDepth(): ProbeResult<{ depth: number; bucketed: number; shape: string }> {
    return probe('stackDepth', () => {
        // A property read on a genuinely-null value, so the throw is a real
        // TypeError with a real stack. Wrapped in a function because TypeScript's
        // control-flow analysis narrows a `const x = null` binding to `never` at the
        // point of use, which would make the deliberate violation uncompilable.
        const nullBinding = (): { missing?: unknown } | null => null;
        const readMissing = (): unknown => nullBinding()?.missing;

        const depthOf = (): number => {
            try {
                readMissing();
            } catch (error) {
                return stackLineCount(error);
            }
            return -1;
        };

        const outer = depthOf();

        function nested(): number {
            try {
                readMissing();
            } catch (error) {
                return stackLineCount(error);
            }
            return -1;
        }

        let shape = 'unavailable';
        try {
            (function named(): void {
                try {
                    readMissing();
                } catch (error) {
                    const second = stackLine(error, 1);
                    shape = (second ?? '').trim().replace(/\(.*\)/, '(...)');
                }
            })();
        } catch { /* the frame rendering is the signal; a throw means it is absent */ }

        return {
            depth: outer,
            innerDepth: nested(),
            // Deliberately coarse: 8 buckets, because the measurement's own stability
            // is only 0.78 and anything finer is noise the server would chase.
            bucketed: Math.max(0, Math.min(7, Math.round(outer / 2))),
            shape,
        };
    });
}

/**
 * UA-Client-Hints. 0.005 ms.
 *
 * ## Why the high-entropy call is guarded and the cheap fields are read FIRST
 *
 * The obvious version awaits `getHighEntropyValues()` and only then returns the rest. That
 * is a single-point bypass of three server rules — `brands_vs_ch_header`, `ua_vs_ch_brand`
 * and `ua_vs_ch_major` — and it costs the attacker one property assignment:
 *
 *     Object.defineProperty(navigator, 'userAgentData', {
 *         value: { brands: [SOME_PLAUSIBLE_BRAND_LIST], mobile: false, platform: 'Windows' },
 *     });
 *
 * No method, so the call throws, `probeAsync` records nothing, and `brands` — the field all
 * three rules read — is never sent. The server then sees no Client-Hints signal at all,
 * which is a legitimate state for Firefox and Safari, and so cannot be distinguished from a
 * spoofer. The attacker does not have to make the brands WRONG; removing the method is
 * enough, which makes it strictly cheaper than the cross-check it defeats.
 *
 * `brands`, `mobile` and `platform` are plain synchronous properties on the object, so
 * nothing about them requires the promise. Reading them before the call means the one
 * thing an attacker cannot avoid is the only thing the server compares.
 */
export function uaClientHints(): Promise<ProbeResult<Record<string, unknown>>> {
    return probeAsync('uaClientHints', async () => {
        const uad = (navigator as NavigatorWithUserAgentData).userAgentData;
        if (!uad) {
            // Not a failure: Firefox and Safari do not implement it, and that
            // absence is itself the signal. The server compares it against what the
            // transport saw in Sec-CH-UA.
            return { supported: false };
        }

        // Read FIRST, and each in its own guard. A spoofer may hand over an object whose
        // `brands` getter throws, or whose `platform` is not a string, and a failure in any
        // one field must not take the others — or the probe — down with it. This case is
        // not hypothetical: a getter that throws is a one-line way to break a naive reader,
        // and the whole point of the rearrangement is that the cheap fields cannot be
        // switched off.
        const read = <T>(fn: () => T, fallback: T): T => {
            try {
                return fn();
            } catch {
                return fallback;
            }
        };

        const brands = read(() => (Array.isArray(uad.brands) ? uad.brands.map((b) => ({ ...b })) : null), null);
        const mobile = read(() => (typeof uad.mobile === 'boolean' ? uad.mobile : null), null);
        const platform = read(() => (typeof uad.platform === 'string' ? uad.platform : null), null);

        // THEN the high-entropy call, in its own guard. Absent in Firefox and Safari, and
        // the first thing a spoofer removes.
        let high: Record<string, unknown> | null = null;
        try {
            if (typeof uad.getHighEntropyValues === 'function') {
                high = (await uad.getHighEntropyValues([
                    'architecture', 'bitness', 'model', 'platformVersion',
                    'uaFullVersion', 'fullVersionList', 'wow64', 'formFactors',
                ] as never)) as unknown as Record<string, unknown>;
            }
        } catch {
            // Deliberately swallowed, and the swallowing is the point: the three rules
            // that read `brands` must not go dark because this failed. `high: null` is a
            // fact the server can see, and `ua_vs_ch_major` already treats a missing
            // high-entropy value as "cannot tell" rather than as a contradiction.
        }

        return {
            supported: true,
            brands,
            mobile,
            platform,
            high,
        };
    });
}

/** Media codec support. 0.060 ms, 3 classes, value score 617.3. */
export function codecs(): ProbeResult<string> {
    return probe('codecs', () => {
        const audio = document.createElement('audio');
        const types = [
            'audio/ogg; codecs="vorbis"', 'audio/ogg; codecs="opus"', 'audio/mpeg',
            'audio/mp4; codecs="mp4a.40.2"', 'audio/wav; codecs="1"', 'audio/flac',
            'audio/webm; codecs="opus"', 'video/ogg; codecs="theora"',
            'video/mp4; codecs="avc1.42E01E, mp4a.40.2"', 'video/mp4; codecs="hev1.1.6.L93.B0"',
            'video/mp4; codecs="av01.0.05M.08"', 'video/webm; codecs="vp8, vorbis"',
            'video/webm; codecs="vp9, opus"', 'video/webm; codecs="av01.0.05M.08"',
            'video/mp4; codecs="hvc1.1.6.L93.B0"', 'application/x-mpegURL',
            'application/vnd.apple.mpegurl',
        ];

        return types.map((type) => `${type.slice(0, 30)}=${audio.canPlayType(type) || 'no'}`).join('|');
    });
}

/** Realtime `AudioContext` parameters. 0.102 ms, 3 classes, value score 573.8. */
export function audioRealtime(): ProbeResult<Record<string, unknown>> {
    return probe('audioRealtime', () => {
        const Ctor = (window.AudioContext ??
            (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext) as
            | typeof AudioContext
            | undefined;
        if (!Ctor) throw new Error('no AudioContext');

        const context = new Ctor();
        try {
            const destination = context.destination;
            return {
                sampleRate: context.sampleRate,
                maxChannelCount: destination.maxChannelCount,
                channelCount: destination.channelCount,
                channelCountMode: destination.channelCountMode,
                channelInterpretation: destination.channelInterpretation,
                numberOfInputs: destination.numberOfInputs,
                numberOfOutputs: destination.numberOfOutputs,
                baseLatency: context.baseLatency,
                outputLatency: context.outputLatency,
            };
        } finally {
            // Closed so a long-lived page does not accumulate live audio contexts,
            // which browsers cap at around six.
            void context.close();
        }
    });
}

/** Screen, viewport and the identity fields a spoofer must fill in. */
export function environment(): ProbeResult<Record<string, unknown>> {
    return probe('environment', () => ({
        screen: {
            width: screen.width,
            height: screen.height,
            availWidth: screen.availWidth,
            availHeight: screen.availHeight,
            availLeft: (screen as ScreenWithAvail).availLeft,
            availTop: (screen as ScreenWithAvail).availTop,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth,
        },
        viewport: {
            innerWidth,
            innerHeight,
            outerWidth,
            outerHeight,
            devicePixelRatio,
            innerWidthRatio: Math.round((outerWidth / Math.max(1, innerWidth)) * 1e4) / 1e4,
        },
        identity: {
            userAgent: navigator.userAgent,
            appVersion: navigator.appVersion,
            appName: navigator.appName,
            appCodeName: navigator.appCodeName,
            product: navigator.product,
            productSub: navigator.productSub,
            vendor: navigator.vendor,
            vendorSub: navigator.vendorSub,
            platform: navigator.platform,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            webdriver: navigator.webdriver,
            hardwareConcurrency: navigator.hardwareConcurrency,
            // Bucketised to 8 values by the platform, which is why it is nearly
            // worthless alone and only useful as a cross-check.
            deviceMemory: (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? null,
            maxTouchPoints: navigator.maxTouchPoints,
            language: navigator.language,
            languages: navigator.languages ? Array.from(navigator.languages) : null,
            pdfViewerEnabled: navigator.pdfViewerEnabled,
        },
        // Count and names only. The full name/description/mimetype structure is a
        // frozen constant in Chrome - exactly five entries since 2015 - so hashing
        // it spends bytes on a constant. The names matter as a contradiction input:
        // a Chrome that reports the PDF plugin set must also report
        // pdfViewerEnabled true, and a measured spoofer did exactly that and missed
        // the second half.
        plugins: {
            length: navigator.plugins.length,
            names: Array.from(navigator.plugins).map((plugin) => plugin.name),
        },
    }));
}

/** Permission-state vector. 1.042 ms, 3 classes. See REPORT.md 7.7. */
export function permissions(): Promise<ProbeResult<Record<string, unknown>>> {
    return probeAsync('permissions', async () => {
        const notificationPermission = readNotificationPermission();
        if (!navigator.permissions) return { supported: false, notificationPermission };

        const names = [
            'geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read',
            'clipboard-write', 'background-sync', 'bluetooth', 'hid', 'midi',
            'payment-handler', 'persistent-storage', 'push', 'screen-wake-lock',
            'storage-access', 'window-management', 'local-fonts',
            'top-level-storage-access', 'accelerometer', 'gyroscope', 'magnetometer',
            'display-capture', 'fullscreen', 'gamepad', 'pointer-lock', 'web-share',
        ];

        const settled = await Promise.all(
            names.map(async (name) => {
                try {
                    const status = await navigator.permissions.query({ name: name as PermissionName });
                    return [name, status.state] as const;
                } catch {
                    return [name, 'unsupported'] as const;
                }
            }),
        );

        // The whole VECTOR is the signal; the individual states are not. A naive
        // spoofer that overrides the whole list to "prompt" is distinguishable,
        // because no real browser answers prompt for names it does not implement.
        return {
            supported: true,
            states: settled.map(([name, state]) => `${name}=${state}`).join(','),
            prompt: settled.filter(([, state]) => state === 'prompt').length,
            denied: settled.filter(([, state]) => state === 'denied').length,
            granted: settled.filter(([, state]) => state === 'granted').length,
            unsupported: settled.filter(([, state]) => state === 'unsupported').length,
            notificationPermission,
        };
    });
}

/**
 * `Notification.permission`, for the server's comparison with the `notifications` entry of
 * the `states` vector above. Null when `Notification` is undefined (Android WebView, and
 * iOS Safari outside a home-screen web app) or when the value is not one of the three the
 * specification defines.
 *
 * Why it is here: headless Chromium answered `permissions.query({name:'notifications'})`
 * with `prompt` while `Notification.permission` said `denied` — two views of ONE setting
 * that a real browser keeps equal. CreepJS reads that pair as `hasPermissionsBug`. This
 * probe only reports the value; whether the pair disagrees is the server's rule, so a fix
 * in a future headless build does not need a client release.
 */
function readNotificationPermission(): 'default' | 'denied' | 'granted' | null {
    try {
        if (typeof Notification === 'undefined') return null;
        const value: unknown = Notification.permission;

        return value === 'default' || value === 'denied' || value === 'granted' ? value : null;
    } catch {
        return null;
    }
}

/** How long `voices` waits for `voiceschanged` when the first `getVoices()` is empty. */
export const VOICES_WAIT_MS = 300;

/**
 * Speech-synthesis voices, counted and hashed without the cloud entries.
 *
 * This is an OS/hardware fact, not a browser preference: the set of installed system
 * voices changes with the OS image, installed language packs and accessibility tools.
 * Chrome's network voices (names starting with `Google`) are excluded because they are
 * not a property of the device; a browser that only exposes those reports `osCount: 0`.
 *
 * The wait is why this is tier 2. `getVoices()` is allowed to return an empty list
 * before the engine has loaded its voice list, and the only reliable way to tell "not
 * loaded yet" from "none installed" is to wait for `voiceschanged` with a timeout.
 * `VOICES_WAIT_MS` is WAIT, not work, so it does not add to the CPU sum in the module
 * docblock and it runs in idle time with the rest of tier 2.
 *
 * An empty list is `unavailable`, never a value. "No speech backend", "timed out" and
 * "this OS genuinely has no voices" (Brave, some Linux images) are different facts, and
 * hashing an empty list would make all three look like two devices AGREEING on a
 * default. The listener is removed on every path, including the timeout path.
 */
export function voices(): Promise<ProbeResult<{ count: number; osCount: number; osHash: string }>> {
    const synth = (window as Window & { speechSynthesis?: SpeechSynthesis }).speechSynthesis;
    if (!synth || typeof synth.getVoices !== 'function') {
        return Promise.resolve(unavailable('no-speech-synthesis'));
    }

    return (async (): Promise<ProbeResult<{ count: number; osCount: number; osHash: string }>> => {
        let list: SpeechSynthesisVoice[];
        try {
            list = synth.getVoices();
        } catch (error) {
            return failed(error);
        }

        let timedOut = false;
        if (list.length === 0) {
            let timer: ReturnType<typeof setTimeout> | undefined;
            timedOut = await new Promise<boolean>((resolve) => {
                const done = (byTimer: boolean): void => {
                    if (timer !== undefined) {
                        clearTimeout(timer);
                    }
                    try {
                        synth.removeEventListener('voiceschanged', onChange);
                    } catch {
                        // A target that cannot remove has nothing registered.
                    }
                    resolve(byTimer);
                };
                const onChange = (): void => done(false);
                timer = setTimeout(() => done(true), VOICES_WAIT_MS);
                try {
                    synth.addEventListener('voiceschanged', onChange);
                } catch {
                    done(true);
                }
            });

            try {
                list = synth.getVoices();
            } catch (error) {
                return failed(error);
            }
        }

        if (list.length === 0) {
            return unavailable(timedOut ? 'timeout' : 'empty');
        }

        const osNames = list
            .map((voice) => voice.name)
            .filter((name) => !name.startsWith('Google'))
            .sort();

        return ok({
            count: list.length,
            osCount: osNames.length,
            osHash: fnv1a32(osNames.join('|')),
        });
    })();
}

/**
 * The bundled tzdata and ICU build fingerprint. 0.1 ms, three-way discriminating.
 *
 * From notes/15 item 1, measured in Chromium/Firefox/WebKit:
 *
 *     tzdata zone count   418   445   444
 *     Europe/Kyiv present  no    yes   yes
 *     icu calendars         18    16    16
 *     icu collations        10    11    12
 *     icu currencies       159   307   307
 *     icu numbering systems 78   78    77
 *
 * The currency count is the valuable one and it is not a locale setting. 159 against 307
 * is a *build configuration* — Chromium ships a reduced ICU, Firefox and WebKit the full
 * one. No amount of property rewriting reproduces it without knowing which build the
 * browser is, and a spoofer has no reason to look.
 *
 * `Europe/Kyiv` is the same idea at one bit: a tzdata *rename* discriminates, so the
 * signal tracks the build rather than the user.
 *
 * What is deliberately NOT collected: the user's own timezone, locale or region. Those are
 * places, not devices, and a value that changes because someone flew to another country
 * would fork the identifier for a reason that has nothing to do with the hardware. The
 * `intl` probe already reads the resolved zone for exactly that reason; this probe reads
 * the size of the *database*, which is a property of the binary.
 */
export function buildFingerprint(): ProbeResult<Record<string, string>> {
    return probe('buildFingerprint', () => {
        const out: Record<string, string> = {};

        if (typeof Intl.supportedValuesOf !== 'function') {
            return { supported: 'no' };
        }

        for (const kind of ['calendar', 'collation', 'currency', 'numberingSystem', 'unit'] as const) {
            try {
                out[kind] = String(Intl.supportedValuesOf(kind).length);
            } catch {
                // A kind the engine exposes but rejects. Recorded as a value because
                // "throws for collation" and "has no collation" are different builds.
                out[kind] = 'err';
            }
        }

        // The timezone set, counted and probed for a few specific renames. The count is
        // the version; the booleans are cheap corroboration that survive a count change.
        try {
            const zones = Intl.supportedValuesOf('timeZone');
            out.tzCount = String(zones.length);
            out.tzKyiv = String(zones.includes('Europe/Kyiv'));
            out.tzKiev = String(zones.includes('Europe/Kiev'));
            out.tzShanghai = String(zones.includes('Asia/Shanghai'));
        } catch {
            out.tzCount = 'err';
        }

        return out;
    });
}

/**
 * The shape of the objects we already read. 1 ms, three-way discriminating.
 *
 * From notes/15 item 2, as MEASURED for this function:
 *
 *     navigator properties  82   48   30
 *     document properties   251  232  233
 *     screen properties     12   16   10
 *
 * (notes/15 also lists `window own properties 1232/988/856`. That row is measured but this
 * function does not return it — it was dropped when the candidate became a probe, because a
 * count of `window` own properties is dominated by per-page and per-extension entries rather
 * than by anything about the browser. The row stays in the note because it is a real
 * measurement; it is not in the claim set.)
 *
 * This is a cross-consistency signal rather than another device value, which is what makes
 * it worth its cost. A spoofer that patches `navigator.userAgent` in place leaves the shape
 * intact; one that rebuilds `navigator` as a plain object does not, and the count is a cheap
 * detector for the second kind. `environment` already reads the *values* off these objects
 * and knows nothing about how many there are.
 *
 * Counts, not names: the names are a long, version-coupled list that would inflate the
 * envelope and fork on every engine release, which is the same trap `dateParsing`'s
 * docblock warns about. A count is one number that still separates the engines.
 *
 * KNOWN LIMITATION, because it is the mirror image of the one above. A count is shorter than
 * a name list, not more stable: `Document.prototype` gains members on a schedule, so this
 * value WILL fork every device on some future engine release. The transport harness checks
 * stability across reloads, which is the weaker property and the one that does not catch it.
 * If that fork becomes a problem, the fix is to bucket the count rather than to remove the
 * probe, and the decision belongs with the volatility measurement in notes/15 §A.
 */
export function objectShape(): ProbeResult<Record<string, number | string>> {
    return probe('objectShape', () => {
        const count = (proto: unknown): number => {
            try {
                return proto && typeof proto === 'object'
                    ? Object.getOwnPropertyNames(proto).length
                    : -1;
            } catch {
                return -1;
            }
        };

        return {
            navigator: count(typeof Navigator === 'function' ? Navigator.prototype : null),
            document: count(typeof Document === 'function' ? Document.prototype : null),
            screen: count(typeof Screen === 'function' ? Screen.prototype : null),
            // Two cheap shape facts rather than more counts. `chrome` exists as an object
            // in Chromium only, and `onbeforeinstallprompt` in Chromium only — a spoofer
            // emulating a Chromium UA has to add both, and usually adds one.
            hasChromeObject: typeof (window as unknown as { chrome?: unknown }).chrome,
            hasInstallPrompt: String('onbeforeinstallprompt' in window),
        };
    });
}

/**
 * The fingerprint of what has been REMOVED. 0.5 ms, three-way discriminating.
 *
 * Every other probe in this file is a *presence* test, and presence is the easy half to
 * fake: the feature list of any browser is public, so copying it requires no knowledge.
 * This one reads the boundaries instead. Measured in the three engines, six of fifteen keys
 * differ, and every one of them is a removal or an unprefixing pinned to a version:
 *
 *     webkitRequestFileSystem   chromium function   —  (removed in Safari 17)
 *     window.safari            —                    —    webkit object  (old Notification ctor)
 *     webkitSpeechRecognition  chromium function   —             (unprefixed in Chrome 139)
 *     window.external          object               object        webkit —  (removed in Safari 18)
 *     -webkit-backdrop-filter  —                    —    webkit true  (unprefixed in Chrome 76)
 *     -webkit-text-size-adjust chromium true        firefox true  webkit —
 *
 * A spoofer claiming to be Chrome 139 has to get the *omissions* right as well as the
 * presences, and enumerating what a browser has deleted is much less common practice than
 * enumerating what it has. The `esFeatures` probe is a 79-entry presence matrix; this is
 * its complement, and it is the half with better economics.
 *
 * Distinct from `esFeatures` even where the names look related: that probe asks whether
 * `backdrop-filter` is supported, this asks whether the *prefixed* spelling still exists in
 * `CSSStyleDeclaration`. Both can be true, and they change in different releases.
 */
export function removedApiBoundary(): ProbeResult<Record<string, string>> {
    return probe('removedApiBoundary', () => {
        const style = document.body.style;
        const win = window as unknown as Record<string, unknown>;
        const has = (obj: object, key: string): string => String(key in obj);

        return {
            // Removed outright, or never in this engine. The boundary is the version.
            webkitRequestFileSystem: typeof win.webkitRequestFileSystem,
            safariNotification: typeof win.safari,
            webkitSpeechRecognition: typeof win.webkitSpeechRecognition,
            msIndexedDB: typeof win.msIndexedDB,
            external: typeof win.external,
            showModalDialog: typeof win.showModalDialog,
            appCache: has(window, 'applicationCache'),
            documentMode: typeof (document as unknown as Record<string, unknown>).documentMode,
            // The old prefixed form of execCommand's sibling, plus two of the prefixes that
            // have been unprefixed engine by engine. `mozAppearance` never shipped in
            // Blink or WebKit, so its absence is a Gecko boundary.
            mozAppearance: has(style, 'MozAppearance'),
            webkitAppearanceLegacy: has(style, 'webkitAppearance'),
            backdropPrefixed: has(style, 'webkitBackdropFilter'),
            textSizeAdjustPrefixed: has(style, 'webkitTextSizeAdjust'),
            // The value object must be read from a real element or `in` misses inherited
            // properties, which is the mistake that would make every key read false.
            execCommand: typeof document.execCommand,
        };
    });
}

// =====================================================================
// TIER 2 - expensive, deferred
// =====================================================================

const SOFTWARE_RENDERER = /swiftshader|llvmpipe|softpipe|lavapipe|\bwarp\b|basic render|software rasterizer|mesa offscreen/i;

const clampGpuString = (value: unknown): string => {
    const text = typeof value === 'string' ? value : String(value ?? '');

    return text.length > 256 ? text.slice(0, 256) : text;
};

/**
 * A trimmed WebGL fingerprint: renderer identity, precision, limits and extension count.
 *
 * This is the probe the server's `renderer_vs_limits` and `ch_platform_vs_gpu` rules use.
 * It deliberately does NOT render or read pixels: `gpuMath`-style rasterisation
 * is a separate, much more expensive probe in the Nutricompare hardware collector, and the
 * point here is the cheap device/OS identity that WebGL exposes. Every value is read once
 * from a 1x1 context and the context is released in `finally`.
 *
 * Cost is front-loaded: the first WebGL context on a page can take 10-100 ms cold on a
 * software rasteriser and ~1-2 ms once a context exists. That is why it is tier 2 and runs
 * in idle time rather than in the synchronous tier; it is not on a user's critical path.
 *
 * Renderer strings are capped at 256 characters. `software` is a server-rule hint, not a
 * decision: SwiftShader/llvmpipe are real renderers on VMs and remote desktops, so a
 * software result is legitimate and must not be treated as tampering on its own.
 */
export function gpu(): ProbeResult<Record<string, unknown>> {
    let canvas: HTMLCanvasElement | undefined;
    let gl: WebGLRenderingContext | WebGL2RenderingContext | null = null;

    try {
        canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
    } catch (error) {
        return failed(error);
    }

    try {
        gl = canvas.getContext('webgl2') as WebGLRenderingContext | WebGL2RenderingContext | null;
    } catch {
        gl = null;
    }

    if (!gl) {
        try {
            gl = (canvas.getContext('webgl') ??
                canvas.getContext('experimental-webgl')) as WebGLRenderingContext | WebGL2RenderingContext | null;
        } catch (error) {
            return failed(error);
        }
    }

    if (!gl) {
        return unavailable('no-webgl');
    }

    const context = gl;

    try {
        const debug = context.getExtension('WEBGL_debug_renderer_info') as
            | { UNMASKED_VENDOR_WEBGL: number; UNMASKED_RENDERER_WEBGL: number }
            | null;
        const vendor = clampGpuString(
            debug ? context.getParameter(debug.UNMASKED_VENDOR_WEBGL) : context.getParameter(context.VENDOR),
        );
        const renderer = clampGpuString(
            debug ? context.getParameter(debug.UNMASKED_RENDERER_WEBGL) : context.getParameter(context.RENDERER),
        );

        const numberParam = (name: string): number => {
            const value = context.getParameter((context as unknown as Record<string, number>)[name]);

            return typeof value === 'number' ? value : -1;
        };
        const rangeParam = (name: string): string => {
            const value = context.getParameter((context as unknown as Record<string, number>)[name]);

            return ArrayBuffer.isView(value)
                ? Array.from(value as unknown as ArrayLike<number>).join(',')
                : String(value);
        };
        const precision = (shader: number): string => {
            const format = context.getShaderPrecisionFormat(shader, context.HIGH_FLOAT);

            return format ? `${format.rangeMin},${format.rangeMax},${format.precision}` : 'none';
        };

        const limitNames = [
            'MAX_TEXTURE_SIZE',
            'MAX_RENDERBUFFER_SIZE',
            'MAX_VERTEX_ATTRIBS',
            'MAX_VERTEX_UNIFORM_VECTORS',
            'MAX_FRAGMENT_UNIFORM_VECTORS',
            'MAX_VARYING_VECTORS',
            'MAX_TEXTURE_IMAGE_UNITS',
            'MAX_COMBINED_TEXTURE_IMAGE_UNITS',
            'MAX_CUBE_MAP_TEXTURE_SIZE',
            'MAX_VERTEX_TEXTURE_IMAGE_UNITS',
        ] as const;
        const limits: Record<string, number> = {};
        for (const name of limitNames) {
            limits[name] = numberParam(name);
        }

        const bitNames = ['RED_BITS', 'GREEN_BITS', 'BLUE_BITS', 'ALPHA_BITS', 'DEPTH_BITS', 'STENCIL_BITS'] as const;
        const bits: Record<string, number> = {};
        for (const name of bitNames) {
            bits[name] = numberParam(name);
        }

        const anisotropic =
            context.getExtension('EXT_texture_filter_anisotropic') ??
            context.getExtension('WEBKIT_EXT_texture_filter_anisotropic') ??
            context.getExtension('MOZ_EXT_texture_filter_anisotropic');
        const anisotropyName = (anisotropic as { MAX_TEXTURE_MAX_ANISOTROPY_EXT?: number } | null)
            ?.MAX_TEXTURE_MAX_ANISOTROPY_EXT;
        const maxAnisotropy =
            anisotropic && typeof anisotropyName === 'number'
                ? context.getParameter(anisotropyName)
                : null;

        return ok({
            vendor,
            renderer,
            webgl2: typeof WebGL2RenderingContext === 'function' && context instanceof WebGL2RenderingContext,
            version: clampGpuString(context.getParameter(context.VERSION)),
            shadingLanguageVersion: clampGpuString(context.getParameter(context.SHADING_LANGUAGE_VERSION)),
            precision: {
                frag: precision(context.FRAGMENT_SHADER),
                vert: precision(context.VERTEX_SHADER),
            },
            limits,
            bits,
            aliasedLineWidthRange: rangeParam('ALIASED_LINE_WIDTH_RANGE'),
            aliasedPointSizeRange: rangeParam('ALIASED_POINT_SIZE_RANGE'),
            maxViewportDims: rangeParam('MAX_VIEWPORT_DIMS'),
            extensionCount: (context.getSupportedExtensions() ?? []).length,
            antialias: context.getContextAttributes()?.antialias ?? null,
            maxAnisotropy: typeof maxAnisotropy === 'number' ? maxAnisotropy : null,
            debugRendererInfo: debug !== null,
            software: SOFTWARE_RENDERER.test(renderer),
        });
    } catch (error) {
        return failed(error);
    } finally {
        try {
            (context.getExtension('WEBGL_lose_context') as { loseContext(): void } | null)?.loseContext();
        } catch {
            // A context that cannot be released has nothing to release.
        }
        if (canvas) {
            canvas.width = 0;
            canvas.height = 0;
        }
    }
}

/** How long `webrtc` waits for an offer before giving up. */
export const WEBRTC_TIMEOUT_MS = 1500;

interface WebRtcCodec {
    readonly mimeType: string;
    readonly clockRate: number;
    readonly channels: number | null;
    readonly fmtp: string;
    readonly feedback: string;
}

/**
 * Parse only the capability part of an SDP offer.
 *
 * This deliberately ignores `a=candidate` lines and the ICE credentials. The goal is the
 * codec/extension set that describes the browser's media stack, not the visitor's network;
 * a candidate line is exactly the thing that would leak a LAN address and is therefore
 * never read, hashed or sent.
 */
function parseWebRtcSdp(sdp: string): Record<string, unknown> {
    const lines = sdp.split(/\r?\n/);
    const payloads: Record<'audio' | 'video', Set<string>> = {
        audio: new Set<string>(),
        video: new Set<string>(),
    };

    for (const line of lines) {
        const match = /^m=(audio|video) \S+ \S+ (.*)$/.exec(line);
        if (match === null) {
            continue;
        }

        const kind = match[1] as 'audio' | 'video';
        for (const payload of match[2].split(/\s+/)) {
            if (/^\d+$/.test(payload)) {
                payloads[kind].add(payload);
            }
        }
    }

    const codecOf = (kind: 'audio' | 'video', payload: string): WebRtcCodec | null => {
        const rtpmap = lines.find((line) => line.startsWith(`a=rtpmap:${payload} `));
        if (rtpmap === undefined) {
            return null;
        }

        const encoding = (rtpmap.split(' ')[1] ?? '').split('/');
        const mimeType = `${kind}/${encoding[0] ?? 'unknown'}`;
        const clockRate = Number(encoding[1] ?? 0);
        const channels = kind === 'audio' ? Number(encoding[2] ?? 1) : null;
        const fmtp = lines
            .filter((line) => line.startsWith(`a=fmtp:${payload} `))
            .map((line) => line.slice(`a=fmtp:${payload} `.length))
            .sort()
            .join('|');
        const feedback = lines
            .filter((line) => line.startsWith(`a=rtcp-fb:${payload} `))
            .map((line) => line.slice(`a=rtcp-fb:${payload} `.length))
            .sort()
            .join('|');

        return { mimeType, clockRate, channels, fmtp, feedback };
    };

    const codecs = (kind: 'audio' | 'video'): WebRtcCodec[] =>
        [...payloads[kind]]
            .map((payload) => codecOf(kind, payload))
            .filter((codec): codec is WebRtcCodec => codec !== null)
            .sort((a, b) => `${a.mimeType}:${a.clockRate}`.localeCompare(`${b.mimeType}:${b.clockRate}`));

    const extensions = lines
        .filter((line) => line.startsWith('a=extmap:'))
        .map((line) => line.split(' ').slice(1).join(' '))
        .sort();

    const audio = codecs('audio');
    const video = codecs('video');
    const capabilityLines = lines
        .filter((line) => /^(m=|a=rtpmap:|a=fmtp:|a=rtcp-fb:|a=extmap:)/.test(line))
        .sort();

    return {
        audio: { count: audio.length, hash: fnv1a32(JSON.stringify(audio)) },
        video: { count: video.length, hash: fnv1a32(JSON.stringify(video)) },
        extensions: { count: extensions.length, hash: fnv1a32(JSON.stringify(extensions)) },
        sdpHash: fnv1a32(capabilityLines.join('\n')),
    };
}

/**
 * The WebRTC media-stack fingerprint: codecs, feedback and RTP extensions.
 *
 * The probe creates a data channel and a local offer with no ICE servers, reads only the
 * SDP capability lines, and closes the peer immediately. It does not await ICE gathering,
 * does not read `a=candidate`, and never touches `localDescription.sdp` after filtering —
 * so no host address, mDNS name or candidate pair can enter the claim set. This is the
 * privacy-safe half of what the commercial SDKs in the catalogue use WebRTC for.
 *
 * The signal identifies the browser/OS media stack (which codecs and extensions exist),
 * not the network. It is tier 2 because constructing a peer and generating an offer is
 * asynchronous and can take tens of milliseconds on a cold stack.
 */
export async function webrtc(): Promise<ProbeResult<Record<string, unknown>>> {
    const constructor = (window.RTCPeerConnection ??
        (window as Window & { webkitRTCPeerConnection?: typeof RTCPeerConnection }).webkitRTCPeerConnection) as
        | typeof RTCPeerConnection
        | undefined;

    if (constructor === undefined) {
        return unavailable('no-webrtc');
    }

    let peer: RTCPeerConnection | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;

    try {
        peer = new constructor({ iceServers: [] });
        peer.createDataChannel('fingerprint');

        const offer = await Promise.race([
            peer.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true }),
            new Promise<never>((_, reject) => {
                timer = setTimeout(() => reject(new Error('webrtc-timeout')), WEBRTC_TIMEOUT_MS);
            }),
        ]);

        await peer.setLocalDescription(offer);
        const sdp = peer.localDescription?.sdp ?? offer.sdp ?? '';

        if (sdp === '') {
            return unavailable('no-sdp');
        }

        return ok(parseWebRtcSdp(sdp));
    } catch (error) {
        return failed(error);
    } finally {
        if (timer !== undefined) {
            clearTimeout(timer);
        }
        try {
            peer?.close();
        } catch {
            // A peer that cannot close has nothing left to release.
        }
    }
}

/**
 * Canvas GEOMETRY, not canvas text. 0.450 ms, 3 classes, value score 363.9.
 *
 * The measured reason for preferring it: cross-load stability of geometry was
 * **1.00** while a text-bearing canvas probe scored **0.67** — its hash changed
 * between two page loads in 8 of 24 cells, because the font stack resolves
 * differently between loads. That reproduces the FP-Stud result locally and
 * indicts the most widely deployed fingerprinting technique. If a text canvas is
 * used at all it must be bucketed, and this probe deliberately excludes text.
 */
export function canvasGeometry(): ProbeResult<Record<string, unknown>> {
    return probe('canvasGeometry', () => {
        const canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 200;
        const context = canvas.getContext('2d');
        if (!context) throw new Error('no 2d context');

        context.fillStyle = '#000';
        context.fillRect(0, 0, 200, 200);
        context.strokeStyle = '#fff';
        context.lineWidth = 1.1;
        // Fractional and half-pixel coordinates exercise the rasteriser's snapping.
        context.beginPath();
        context.arc(100.5, 100.25, 50.5, 0, Math.PI * 1.7);
        context.stroke();
        context.beginPath();
        context.moveTo(0.5, 0.5);
        context.bezierCurveTo(20.25, 40.75, 120.5, 5.5, 199.5, 90.25);
        context.stroke();
        context.globalCompositeOperation = 'multiply';
        context.fillStyle = 'rgba(255,0,0,0.5)';
        context.fillRect(20, 20, 80, 80);
        context.globalCompositeOperation = 'lighter';
        context.fillStyle = 'rgba(0,0,255,0.5)';
        context.fillRect(80, 80, 80, 80);

        const data = context.getImageData(0, 0, 200, 200).data;
        let hash = 0x811c9dc5;
        let sum = 0;
        for (let index = 0; index < data.length; index += 4) {
            hash = Math.imul(hash ^ (data[index] as number), 16777619) >>> 0;
            sum += data[index] as number;
        }

        return {
            hash: (hash >>> 0).toString(16),
            redSum: sum,
            // Context-creation support, which is cheap and separates a real
            // compositor from a stub.
            supportsOffscreen: typeof OffscreenCanvas === 'function',
            supportsWebgl2: (() => {
                try {
                    return !!document.createElement('canvas').getContext('webgl2');
                } catch {
                    return false;
                }
            })(),
        };
    });
}

/** Intl and ICU. 1.960 ms, 8 classes. High entropy, and engine-invariant where it matters. */
export function intl(): ProbeResult<Record<string, unknown>> {
    return probe('intl', () => {
        const resolved = Intl.DateTimeFormat().resolvedOptions();

        return {
            resolved: {
                locale: resolved.locale,
                calendar: resolved.calendar,
                numberingSystem: resolved.numberingSystem,
                timeZone: resolved.timeZone,
                hourCycle: resolved.hourCycle,
                hour12: resolved.hour12,
                era: resolved.era,
                weekday: resolved.weekday,
                timeZoneName: resolved.timeZoneName,
            },
            // `maximize()` reveals the likely-subtags REGION even when the locale
            // itself is faked, which is why it is here and plain `language` is not.
            maximize: ['nl-NL', 'en-GB', 'sr-Latn', 'ca-ES', 'az-Arab', 'zh-Hant-TW'].map((locale) => {
                try {
                    return `${locale}>${new Intl.Locale(locale).maximize().toString()}`;
                } catch {
                    // The failure is itself the claim: a build that cannot parse the tag
                    // maximises to a different result than one that can.
                    return `${locale}>error`;
                }
            }),
            // Swedish sorts "ä" after "z"; German sorts it as "a". Nearly free, and
            // it identifies the ICU build.
            collation: [
                new Intl.Collator('nl').compare('a', 'ä'),
                new Intl.Collator('sv').compare('a', 'ä'),
                new Intl.Collator('de').compare('a', 'ä'),
            ].join(','),
            numberFormat: new Intl.NumberFormat('nl-NL').format(1234567.891),
            currency: new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' }).format(1234.5),
            calendars: (() => {
                try {
                    return ['gregory', 'buddhist', 'japanese', 'islamic', 'hebrew', 'persian',
                        'indian', 'coptic', 'ethiopic', 'chinese', 'roc']
                        .map((calendar) => {
                            try {
                                return `${calendar}=${new Intl.DateTimeFormat('en', { calendar: calendar as string }).format(0)}`;
                            } catch {
                                return `${calendar}=e`;
                            }
                        })
                        .join('|');
                } catch {
                    return 'error';
                }
            })(),
            timeZone: (() => {
                // January versus July offset distinguishes southern-hemisphere zones
                // and any offset that was faked without checking DST.
                try {
                    const formatter = new Intl.DateTimeFormat('en', { timeZoneName: 'short' });
                    return {
                        name: resolved.timeZone,
                        offset: new Date().getTimezoneOffset(),
                        januaryOffset: new Date('2024-01-15T12:00:00Z').getTimezoneOffset(),
                        julyOffset: new Date('2024-07-15T12:00:00Z').getTimezoneOffset(),
                        short: formatter.format(new Date()),
                    };
                } catch (error) {
                    return { error: error instanceof Error ? error.name : 'Error' };
                }
            })(),
        };
    });
}

/**
 * The offline-render audio sum. 1.875 ms.
 *
 * The high-entropy audio signal: render an oscillator through a DynamicsCompressor
 * in an OfflineAudioContext and sum a fixed window. Kraken ships this exact value.
 * It is stable across browsers *on the same OS* and varies by the OS audio stack,
 * which makes it a device-and-OS signal rather than an engine one.
 *
 * Note the cost: 1.875 ms for one float, against 0.020 ms for the entire
 * `dateParsing` probe. That is the value-per-millisecond trade in its clearest form.
 */
export function audioOffline(): Promise<ProbeResult<number>> {
    return probeAsync('audioOffline', async () => {
        const OfflineCtor = (window.OfflineAudioContext ??
            (window as unknown as { webkitOfflineAudioContext?: typeof OfflineAudioContext }).webkitOfflineAudioContext) as
            | typeof OfflineAudioContext
            | undefined;
        if (!OfflineCtor) throw new Error('no OfflineAudioContext');

        const context = new OfflineCtor(1, 5000, 44100);
        const oscillator = context.createOscillator();
        oscillator.type = 'triangle';
        oscillator.frequency.value = 10000;

        const compressor = context.createDynamicsCompressor();
        compressor.threshold.value = -50;
        compressor.knee.value = 40;
        compressor.ratio.value = 12;
        compressor.attack.value = 0;
        compressor.release.value = 0.25;

        oscillator.connect(compressor);
        compressor.connect(context.destination);
        oscillator.start(0);

        const buffer = await context.startRendering();
        const channel = buffer.getChannelData(0);

        // Sum only the tail, where the compressor's curve has settled. The head is
        // dominated by the oscillator's attack and is not the stable part.
        let sum = 0;
        for (let index = 4500; index < 5000; index++) {
            sum += Math.abs(channel[index] as number);
        }

        return Math.round(sum * 1e9) / 1e9;
    });
}

/**
 * Font resolution order. 0.320 ms, 3 classes, value score 421.6.
 *
 * Presence enumeration (`document.fonts.check`) gives a *set*; this gives more, by
 * discovering which generic family each named font resolves to. The equality
 * pattern across families is a font-matching-configuration fingerprint, and it is
 * far more stable than absolute widths because a font install usually shifts one
 * family without changing which families collide.
 *
 * Deliberately does NOT enumerate 40+ font names: that measured 190-498 ms for a
 * single discriminating value in a bare container, and it is the most expensive
 * thing in the catalogue by an order of magnitude. Twelve families, resolution
 * based, is the affordable version of the same idea.
 */
export function fontFallback(): ProbeResult<Record<string, unknown>> {
    return probe('fontFallback', () => {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        if (!context) throw new Error('no 2d context');

        const TEXT = 'mmmmmmmmmmlliWWW@#0123456789';
        const width = (family: string): number => {
            context.font = `72px ${family}`;
            return context.measureText(TEXT).width;
        };

        const generics = ['monospace', 'sans-serif', 'serif', 'cursive', 'fantasy', 'system-ui'];
        const base: Record<string, number> = {};
        for (const generic of generics) {
            base[generic] = Math.round(width(generic) * 1e4) / 1e4;
        }

        const resolve: Record<string, unknown> = {};
        for (const family of [
            'Arial', '"Times New Roman"', '"Courier New"', 'Helvetica', 'Georgia',
            'Impact', '"Segoe UI"', 'Tahoma', 'Verdana', 'Roboto', '"MS Gothic"', '"Malgun Gothic"',
        ]) {
            const bare = width(`"${family.replace(/"/g, '')}"`);
            resolve[family] = {
                width: Math.round(bare * 1e4) / 1e4,
                // Which generic it collapses to. A local() source with no fallback
                // measures 0, which is why the width is meaningless on its own.
                collides: generics.filter((generic) => Math.abs(bare - (base[generic] as number)) < 0.01),
            };
        }

        return { base, resolve };
    });
}

/**
 * `navigator.measureUserAgentSpecificMemory`, gated on cross-origin isolation.
 *
 * Requires `COOP: same-origin` and `COEP: require-corp`, and measured 114-243 ms
 * while FAILING on all three engines without them. So the gate is not an
 * optimisation, it is the difference between a signal and three times the budget
 * spent on an error.
 */
export function heapMemory(): Promise<ProbeResult<Record<string, unknown>>> {
    return probeAsync('heapMemory', async () => {
        const measure = (navigator as Navigator & {
            measureUserAgentSpecificMemory?: () => Promise<{ bytes: number; quota: number }>;
        }).measureUserAgentSpecificMemory;

        if (typeof measure !== 'function') {
            return { supported: false, reason: 'not implemented' };
        }
        if (!self.crossOriginIsolated) {
            return { supported: false, reason: 'not cross-origin isolated' };
        }

        const result = await measure.call(navigator);
        return { supported: true, bytes: result.bytes, quota: result.quota };
    });
}

// =====================================================================
// Registry
// =====================================================================

export interface ValueProbe {
    readonly name: string;
    readonly tier: Tier;
    readonly run: () => ProbeResult<unknown> | Promise<ProbeResult<unknown>>;
}

/**
 * The probe set, with the measured cost and value of each recorded.
 *
 * ## Why four probes moved out of tier 1
 *
 * The real-browser check measures COLD cost — the first collection in a fresh page,
 * which is the case that matters, because a user arriving at a sign-in form has not
 * yet paid the platform's one-time initialisation costs. Measured cold:
 *
 * | probe | cold cost | value score | verdict |
 * |---|---|---|---|
 * | `textMetrics` | 11.3 ms | 654 | moved to tier 2 |
 * | `errorText` | 7.9 ms | 509 | moved to tier 2 |
 * | `audioRealtime` | 8.0 ms | 574 | moved to tier 2 |
 * | `permissions` | 12.0 ms | 224 | moved to tier 2 |
 *
 * All four are VALUE probes, and the research measured that no value probe detects
 * an attacker at all — 0 of 162 runs. So paying 39 ms of critical-path time for
 * signals that cannot contribute to tamper detection is a bad trade even before
 * consideration of their individual value scores, and `permissions` at 224 is the
 * worst of the four by value anyway.
 *
 * They are not removed; they are deferred, which is where the design always said
 * non-urgent signals belonged. What was removed was the cost from the path a user is
 * waiting on.
 *
 * `budgetMs` and `measuredValue` are from research/fingerprinting. They are
 * comments rather than assertions here because a probe's cost is machine-specific;
 * tests/Browser/transport-checks.mjs is where the budget is enforced, on all three
 * engines, and that is the check that matters.
 */
export const VALUE_PROBES: readonly ValueProbe[] = [
    // Tier 1 — the synchronous part. All cheap, all stable.
    { name: 'dateParsing', tier: TIER.ONE, run: dateParsing },      // 0.020 ms, value 1014
    { name: 'cssMedia', tier: TIER.ONE, run: cssMedia },            // 0.040 ms, value 606
    { name: 'stackDepth', tier: TIER.ONE, run: stackDepth },        // 0.050 ms, value 736
    { name: 'codecs', tier: TIER.ONE, run: codecs },                // 0.060 ms, value 617
    { name: 'esFeatures', tier: TIER.ONE, run: esFeatures },        // 0.160 ms, value 524
    { name: 'environment', tier: TIER.ONE, run: environment },      // 0.020 ms, identity fields
    { name: 'uaClientHints', tier: TIER.ONE, run: uaClientHints },  // 0.005 ms, value 397
    { name: 'buildFingerprint', tier: TIER.ONE, run: buildFingerprint }, // 0.100 ms, notes/15 §1
    { name: 'objectShape', tier: TIER.ONE, run: objectShape },      // 1.000 ms, notes/15 §2
    { name: 'removedApiBoundary', tier: TIER.ONE, run: removedApiBoundary }, // 0.500 ms, notes/15 §8

    // Tier 2 — deferred to idle time. Includes the four demoted above.
    { name: 'textMetrics', tier: TIER.TWO, run: textMetrics },      // 11.3 ms cold, value 654
    { name: 'errorText', tier: TIER.TWO, run: errorText },          // 7.9 ms cold, value 509
    { name: 'audioRealtime', tier: TIER.TWO, run: audioRealtime },  // 8.0 ms cold, value 574
    { name: 'permissions', tier: TIER.TWO, run: permissions },      // 12.0 ms cold, value 224
    { name: 'voices', tier: TIER.TWO, run: voices },                // up to 300 ms WAIT, not work
    { name: 'gpu', tier: TIER.TWO, run: gpu },                      // est. 10-100 ms cold, 1-2 ms warm; weight nominal
    { name: 'webrtc', tier: TIER.TWO, run: webrtc },                // async offer; no ICE candidates
    { name: 'behavior', tier: TIER.TWO, run: behavior },            // passive aggregates since page load
    { name: 'canvasGeometry', tier: TIER.TWO, run: canvasGeometry },// 0.450 ms warm, value 364
    { name: 'fontFallback', tier: TIER.TWO, run: fontFallback },    // 23.1 ms cold, value 422
    { name: 'intl', tier: TIER.TWO, run: intl },                    // 1.960 ms, value 259
    { name: 'audioOffline', tier: TIER.TWO, run: audioOffline },    // 1.875 ms, value 146
    { name: 'heapMemory', tier: TIER.TWO, run: heapMemory },        // gated on COI
];

/**
 * Run the probes for a tier.
 *
 * Probes within a tier run CONCURRENTLY via Promise.all rather than in sequence,
 * because most of the measured cost is synchronous rasterisation that the event loop
 * cannot overlap anyway, while the async ones (UA-CH, permissions, audio) genuinely
 * can. Running them in parallel keeps the wall-clock close to the slowest probe
 * rather than the sum.
 */
export async function runTier(
    tier: Tier,
): Promise<Record<string, ProbeResult<unknown> | Promise<ProbeResult<unknown>>>> {
    const entries = await Promise.all(
        VALUE_PROBES.filter((entry) => entry.tier === tier).map(
            async (entry) => [entry.name, entry.run()] as const,
        ),
    );

    return Object.fromEntries(entries);
}

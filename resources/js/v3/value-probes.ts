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
 * The server keys are HMACs over the stabilised claim set, so a new probe changes them for
 * every device on deploy. A one-time event rather than a regression, but nothing warns.
 *
 * ## Three tiers
 *
 * - Tier 1 runs synchronously inside `collect()`. Cold (first visit in a fresh renderer) the
 *   whole `collect()` measured 13 ms in Chromium 153, 14 ms in Firefox 155 and 33 ms in
 *   WebKit 26.6 on 2026-10-05, after `buildFingerprint` (10-11 ms cold, ICU load) moved to
 *   tier 2; before that it was 26-37 ms. Both cold and warm numbers are printed by
 *   tests/Browser/transport-checks.mjs on every run; they are machine-specific.
 * - Tier 2 and tier HARDWARE run in idle time through `runDeferred`: one probe (or one step
 *   of a stepped probe) at a time, each started only when the idle deadline still has room
 *   (`IdleDeadline.timeRemaining()`, or a 16 ms budget where `requestIdleCallback` is
 *   absent), the known first-use-expensive probes always at the start of a fresh idle period,
 *   and the audio probes last. A cold first-use cost (an `AudioContext`, the first font
 *   matching) is still paid inside one task — slicing chooses WHEN a probe starts, not how
 *   long it runs — which is why tests/Browser/transport-checks.mjs measures every slice with
 *   the Long Tasks API and ratchets only the warm ones.
 * - Tier HARDWARE holds the engine-independent device/OS signals the cross-browser
 *   `hardware_key` is built from. On the wire both deferred tiers are merged into
 *   `claims.tier2`; the tier only separates scheduling.
 *
 * Cost annotations below are warm figures unless marked cold.
 *
 * ## Every probe reads behaviour the specification leaves unspecified
 *
 * Specified behaviour is byte-identical across engines (measured: RegExp features,
 * structuredClone, TypedArray semantics, Map/Set order, async interleaving) and carries
 * nothing. Rasterisation, font metrics, ICU data, error text and the `Date` fallback
 * parser are unspecified, which is why they still differ.
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
import {
    CANVAS_REALM_HEIGHT,
    CANVAS_REALM_WIDTH,
    canvasRealmHash,
    engineIdentityOf,
    fnv1a32Bytes,
    sanitiseReply,
    spinIterations,
    scopeSnapshot,
    unmaskedWebGl,
    type EngineIdentity,
    type ScopeSnapshot,
} from './realm';
import { CORE_PROBES } from './protocol';
import { onRelease, sharedAudioContext, sharedWebGl, type SharedWebGl } from './shared';
import {
    hasMember,
    type LooseIntlOptions,
    type NavigatorWithUserAgentData,
    type ScreenWithAvail,
    type Uint8ArrayWithBase64,
} from './types';

export const TIER = { ONE: 1, TWO: 2, HARDWARE: 3 } as const;
export type Tier = (typeof TIER)[keyof typeof TIER];

// =====================================================================
// TIER 1 - cheap, synchronous
// =====================================================================

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
 * A feature-presence matrix over ES2022..ES2026, late-stage proposals and current web
 * APIs. 0.160 ms, 3 classes.
 *
 * Its value is as a **version cross-check**: a client claiming to be an old browser
 * while behaving like a new one, paired with `Sec-CH-UA-Full-Version-List`. It forks
 * on every engine release that ships one of these, which is why the server keeps it
 * out of the hardware key.
 *
 * Entries are `1` (present), `0` (absent) or `-1` (the probe threw). Only the names
 * of the PRESENT features are returned. Instance-only properties (`Error#cause`,
 * `AggregateError#errors`) are tested on an instance, and element members on the
 * interface that defines them, because `in SomeOther.prototype` is always false.
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
            // ES2021
            weakRef: has(global, 'WeakRef'),
            finalizationRegistry: has(global, 'FinalizationRegistry'),
            // ES2022
            arrayAt: has(Array.prototype, 'at'),
            errorCause: tryBool(() => 'cause' in new Error('', { cause: 0 })),
            errorErrors: tryBool(() => typeof AggregateError === 'function' && 'errors' in new AggregateError([])),
            regExpHasIndices: has(RegExp.prototype, 'hasIndices'),
            // ES2023
            arrayToSorted: has(Array.prototype, 'toSorted'),
            arrayToReversed: has(Array.prototype, 'toReversed'),
            arrayToSpliced: has(Array.prototype, 'toSpliced'),
            arrayWith: has(Array.prototype, 'with'),
            arrayFindLast: has(Array.prototype, 'findLast'),
            arrayFindLastIndex: has(Array.prototype, 'findLastIndex'),
            // ES2024
            objectGroupBy: has(Object, 'groupBy'),
            promiseWithResolvers: has(Promise, 'withResolvers'),
            arrayBufferResize: has(ArrayBuffer.prototype, 'resize'),
            arrayBufferTransfer: has(ArrayBuffer.prototype, 'transfer'),
            regexpVFlag: tryBool(() => {
                new RegExp('a', 'v');
                return true;
            }),
            stringIsWellFormed: has(String.prototype, 'isWellFormed'),
            stringToWellFormed: has(String.prototype, 'toWellFormed'),
            // ES2025
            iteratorHelpers: has((global.Iterator as { prototype?: object } | undefined)?.prototype ?? {}, 'map'),
            setUnion: has(Set.prototype, 'union'),
            regexpEscape: has(RegExp, 'escape'),
            promiseTry: has(Promise, 'try'),
            float16Array: tryBool(() => {
                new Float16Array(1);
                return true;
            }),
            // ES2026 (stage 4 in 2025)
            uint8FromBase64: tryBool(() => typeof hasMember(Uint8Array as unknown as Uint8ArrayWithBase64, 'fromBase64') === 'function'),
            uint8ToBase64: tryBool(() => typeof hasMember(Uint8Array.prototype as unknown as Uint8ArrayWithBase64, 'toBase64') === 'function'),
            uint8SetFromBase64: tryBool(() => typeof hasMember(Uint8Array.prototype as unknown as Uint8ArrayWithBase64, 'setFromBase64') === 'function'),
            uint8ToHex: tryBool(() => typeof hasMember(Uint8Array.prototype as unknown as Uint8ArrayWithBase64, 'toHex') === 'function'),
            errorIsError: tryBool(() => typeof (Error as { isError?: unknown }).isError === 'function'),
            mathSumPrecise: tryBool(() => typeof (Math as { sumPrecise?: unknown }).sumPrecise === 'function'),
            // Late-stage TC39 proposals (stage as of the engines measured, not final editions)
            arrayFromAsync: has(Array, 'fromAsync'),
            mapGetOrInsert: has(Map.prototype, 'getOrInsert'),
            temporal: tryBool(() => typeof global.Temporal === 'object'),
            disposableStack: tryBool(() => typeof global.DisposableStack === 'function'),
            // Web APIs
            structuredClone: has(global, 'structuredClone'),
            schedulerYield: tryBool(() => typeof (global.scheduler as { yield?: unknown } | undefined)?.yield === 'function'),
            navLocks: tryBool(() => 'locks' in navigator),
            navCredentials: tryBool(() => 'credentials' in navigator),
            navMediaCapabilities: tryBool(() => 'mediaCapabilities' in navigator),
            navUsb: tryBool(() => 'usb' in navigator),
            navSerial: tryBool(() => 'serial' in navigator),
            navHid: tryBool(() => 'hid' in navigator),
            navBluetooth: tryBool(() => 'bluetooth' in navigator),
            navKeyboardLayout: tryBool(() => 'keyboard' in navigator),
            navBattery: tryBool(() => 'getBattery' in navigator),
            navGamepads: tryBool(() => 'getGamepads' in navigator),
            viewTransitions: tryBool(() => typeof (document as Document & { startViewTransition?: unknown }).startViewTransition === 'function'),
            // Invoker commands live on HTMLButtonElement; customizable <select> ships as
            // the HTMLSelectedContentElement interface.
            invokerCommands: tryBool(() => 'command' in HTMLButtonElement.prototype),
            selectedContent: tryBool(() => typeof global.HTMLSelectedContentElement === 'function'),
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
            cssTransitionBehavior: tryBool(() => CSS.supports('transition-behavior: allow-discrete')),
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
                // Truncated by code point, not code unit: a split surrogate pair makes
                // the server's json_decode reject the whole envelope.
                return `${name}|${Array.from(message).slice(0, 70).join('')}`;
            }
        };

        // No WebAssembly case: compiling a module needs `'wasm-unsafe-eval'`, which the
        // strict CSP does not grant, so it fired a violation report on every collection
        // and its text changed with the CSP mode.
        return {
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

/*
 * There is no `stackDepth` probe any more (round-2 review STD-3 / BR-4, removed 2026-10-08).
 * In V8 the value was `Error.stackTraceLimit + 1` whatever the call depth, in JavaScriptCore
 * it was the caller's depth — a property of how the collector was invoked, constant in the
 * most common engine, already excluded from both keys, and read by no server rule. The
 * engine's stack-line FORMAT, the one mark it carried, is `engineIdentity.stackShape`.
 */

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

/**
 * Realtime `AudioContext` parameters. 2 ms warm; 34-210 ms in a cold browser process (the
 * first context starts the OS output path — round-2 PERF-6), which is why the scheduler runs
 * it in the LAST idle slices. Reads the collection's shared context.
 *
 * No `baseLatency` and no `outputLatency` (round-2 BR2-2): both are live estimates of the
 * output path — `outputLatency` measured 0 → 0.032 between two loads of the same Chromium —
 * i.e. measurements, which never belong in a claim set (every page load became a new
 * device in the client digest and the harness went red on it).
 */
export function audioRealtime(): ProbeResult<Record<string, unknown>> {
    return probe('audioRealtime', () => {
        const context = sharedAudioContext();
        if (!context) throw new Error('no AudioContext');

        const destination = context.destination;
        return {
            sampleRate: context.sampleRate,
            maxChannelCount: destination.maxChannelCount,
            channelCount: destination.channelCount,
            channelCountMode: destination.channelCountMode,
            channelInterpretation: destination.channelInterpretation,
            numberOfInputs: destination.numberOfInputs,
            numberOfOutputs: destination.numberOfOutputs,
        };
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

/**
 * Permission-state vector. 1-2 ms warm.
 *
 * Only names in the Permissions registry that `query()` accepts without an extended
 * descriptor. `push`, `fullscreen` and `top-level-storage-access` need extra descriptor
 * members, and `hid`, `gamepad`, `web-share`, `pointer-lock` and `bluetooth` are
 * Permissions-Policy features or unimplemented for `query()`, so they only ever produced
 * a TypeError. States are user and site-policy choices, which is why the server keeps
 * this probe out of both keys.
 */
export function permissions(): Promise<ProbeResult<Record<string, unknown>>> {
    return probeAsync('permissions', async () => {
        const notificationPermission = readNotificationPermission();
        if (!navigator.permissions) return { supported: false, notificationPermission };

        const names = [
            'geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read',
            'clipboard-write', 'persistent-storage', 'midi', 'screen-wake-lock',
            'storage-access', 'accelerometer', 'gyroscope', 'magnetometer', 'local-fonts',
            'window-management', 'display-capture', 'payment-handler', 'background-sync',
        ];

        const settled = await Promise.all(
            names.map(async (name) => {
                try {
                    const status = await navigator.permissions.query({ name: name as PermissionName });
                    return [name, status.state] as const;
                } catch (error) {
                    // The NAME of the error, not a flat `unsupported` (round-2 STD-7): for a
                    // name an engine does not implement, Firefox throws `TypeError` for all of
                    // them while WebKit throws `NotSupportedError` for five (midi, the three
                    // sensors, display-capture) and `TypeError` for the rest — an engine mark
                    // the flat bucket discarded. Read structurally: a DOMException from another
                    // realm is not an `instanceof Error` here.
                    return [name, permissionErrorName(error)] as const;
                }
            }),
        );

        // The whole VECTOR is the signal; the individual states are not. A naive
        // spoofer that overrides the whole list to "prompt" is distinguishable,
        // because no real browser answers prompt for names it does not implement.
        const isState = (state: string): boolean => state === 'prompt' || state === 'denied' || state === 'granted';

        return {
            supported: true,
            states: settled.map(([name, state]) => `${name}=${state}`).join(','),
            prompt: settled.filter(([, state]) => state === 'prompt').length,
            denied: settled.filter(([, state]) => state === 'denied').length,
            granted: settled.filter(([, state]) => state === 'granted').length,
            // Every rejected name, whatever the engine called the error.
            unsupported: settled.filter(([, state]) => !isState(state)).length,
            notificationPermission,
        };
    });
}

/**
 * The error name a rejected `permissions.query()` produced, for the `states` vector. A
 * non-empty string `name` is kept as-is (it is one of the engine's own DOMException or
 * ECMAScript error names); anything else is `unsupported`, which is also what the states
 * vector said for every rejected name before 2026-10-08.
 */
function permissionErrorName(error: unknown): string {
    const name = typeof error === 'object' && error !== null ? (error as { name?: unknown }).name : undefined;

    return typeof name === 'string' && name !== '' ? name : 'unsupported';
}

/**
 * `Notification.permission`, for the server's comparison with the `notifications` entry of
 * the `states` vector above. Null when `Notification` is undefined (Android WebView, and
 * iOS Safari outside a home-screen web app — BCD `api.Notification.permission_static`) or
 * when the value is not one of the three the specification defines.
 *
 * Why it is here: headless Chromium answered `permissions.query({name:'notifications'})`
 * with `prompt` while `Notification.permission` said `denied` — two views of ONE setting
 * that a real browser keeps equal. CreepJS reads that pair as `hasPermissionsBug`
 * (catalogue §4, `likeHeadless`). This probe only reports the value; whether the pair
 * disagrees is the server's rule, so a fix in a future headless build does not need a
 * client release.
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

/**
 * CPU architecture from the sign of the default quiet NaN.
 *
 * `Infinity - Infinity` in a Float32 produces 0xFFC00000 on x86 (sign bit set) and
 * 0x7FC00000 on ARM, so the top byte of the little-endian buffer is 255 or 127. The
 * server cross-checks it against `Sec-CH-UA-Arch` where that witness exists.
 */
export function architecture(): ProbeResult<{ nanSign: 'x86' | 'arm' | 'unknown' }> {
    return probe('architecture', () => {
        const f32 = new Float32Array(1);
        const u8 = new Uint8Array(f32.buffer);
        f32[0] = Infinity;
        f32[0] = (f32[0] as number) - (f32[0] as number);
        const sign = u8[3];

        return { nanSign: sign === 255 ? 'x86' : sign === 127 ? 'arm' : 'unknown' };
    });
}

/**
 * The JavaScript ENGINE, from marks the User-Agent string cannot change. Measured
 * 0.1 ms or less (see tests/Browser/transport-checks.mjs for the per-engine figure).
 *
 * Four raw marks plus the client's own classification (`realm.ts`, `classifyEngine`):
 *
 * - `errorOwnProps` — the own properties of `new Error('x')`. SpiderMonkey adds
 *   `fileName`/`lineNumber`/`columnNumber`, JavaScriptCore adds `line`/`column`/`sourceURL`,
 *   V8 adds only `stack`. These are engine EXTENSIONS, so no specification pins them and
 *   each engine has kept its own for over a decade.
 * - `stackShape` — `    at fn (url)` (V8) versus `fn@url` (SpiderMonkey, JavaScriptCore).
 * - `toFixedMessageLength` — the length of the `(-1).toFixed(-1)` RangeError message,
 *   whose wording is unspecified. The mark CreepJS's `getEngine()` sums with a source
 *   length (80 V8 / 58 SpiderMonkey / 77 JavaScriptCore, catalogue §15).
 * - `internalError` — whether the SpiderMonkey-only `InternalError` global exists.
 *
 * Why it is worth a tier-1 slot: the server compares the engine with the one the UA
 * claims (Chrome/Edge → V8, Firefox → SpiderMonkey, Safari and every iOS browser →
 * JavaScriptCore). Rewriting the UA is one line; making V8 own `lineNumber` on its errors
 * is not something a page script can do for errors the engine itself creates. The server
 * re-derives the engine from the raw marks and ignores `engine`, so a spoofer that edits
 * this result has to fake all four marks consistently.
 *
 * It identifies an engine, never a device: no cross-device tracking value.
 */
export function engineIdentity(): ProbeResult<EngineIdentity> {
    return probe('engineIdentity', () => engineIdentityOf());
}

// =====================================================================
// TIER 2 - expensive, deferred
// =====================================================================

/** How long `workerScope` waits for the worker's reply before reporting `timeout`. */
export const WORKER_SCOPE_TIMEOUT_MS = 1500;

/** `tier2.workerScope` on the wire. Both snapshots have identical keys. */
export interface WorkerScopeValue {
    readonly workerType: 'dedicated';
    readonly window: ScopeSnapshot;
    readonly worker: ScopeSnapshot;
    /** Round trip, construction to reply. Named `elapsedMs` so it is stripped before hashing. */
    readonly elapsedMs: number;
}

const nowMs = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());

/**
 * The page realm's `canvasRealm` hash: a DETACHED `<canvas>` (the element type, so its
 * context is the `CanvasRenderingContext2D` a page-level extension patches), with
 * `willReadFrequently` as in the worker. Null without a 2D context. Never throws.
 */
function windowCanvasHash(): string | null {
    try {
        const canvas = document.createElement('canvas');
        canvas.width = CANVAS_REALM_WIDTH;
        canvas.height = CANVAS_REALM_HEIGHT;
        return canvasRealmHash(canvas.getContext('2d', { willReadFrequently: true }));
    } catch {
        return null;
    }
}

/**
 * Constructs the dedicated scope worker.
 *
 * Production build: a CLASSIC worker. Vite emits the worker chunk as an IIFE
 * (`worker.format` default `iife`), which is what the engines in the supported matrix can
 * run: Firefox 111-113 have no module workers (they arrived in 114), so a
 * `{ type: 'module' }` construction made every one of them report `blocked`. Omitting the
 * option is what Vite reads as "classic" and the constructor then matches the emitted format.
 *
 * Dev server: Vite serves the worker source unbundled, with its `import` statements, which
 * only a module worker can evaluate; there the module form is used. Vite reads the worker
 * type statically from each `new Worker(new URL(...), {...})` call, so the two forms must be
 * two literal calls; `import.meta.env.DEV` is `false` in a build and the module branch is
 * removed from the output.
 */
function createScopeWorker(): Worker {
    return import.meta.env.DEV
        ? new Worker(new URL('./scope.worker.ts', import.meta.url), { type: 'module' })
        : new Worker(new URL('./scope.worker.ts', import.meta.url));
}

/**
 * The same snapshot read in a dedicated worker and in the page. Asynchronous; the cost is
 * mostly the worker's start-up and its own WebGL context, which run OFF the main thread.
 *
 * ## Why
 *
 * Every value probe in this file reads the page's realm, and the page's realm is exactly
 * what a page-level spoofer (an extension content script, a puppeteer-stealth evasion, a
 * userscript) rewrites. A dedicated worker has its own `WorkerNavigator`, `Intl` and
 * `OffscreenCanvas` WebGL. A spoofer that patched the page and not the worker produces two
 * snapshots that disagree on `userAgent`, `platform`, `hardwareConcurrency`, the time zone
 * or the GPU, and the server — not this code — compares them. CreepJS makes the same
 * comparison client-side (catalogue §15; its `hasBadWebGL` stealth key, §4, is the WebGL
 * half); notes/21 §2 item 2 is the rationale for adopting it.
 *
 * ## Shape and order
 *
 * The worker is asked first and the window snapshot is read AFTER its reply, in the same
 * invocation, so the two reads are as close in time as the round trip allows. The window
 * side's WebGL strings come from the collection's shared context (`sharedWebGl()`), not a
 * second context of its own. `elapsedMs` is the round trip and is stripped before
 * hashing by its name.
 *
 * ## Failure is `unavailable`, never a finding
 *
 * - `no-worker`: the engine has no `Worker`.
 * - `blocked`: the constructor threw (CSP, sandboxed iframe, an extension), the worker
 *   fired `error` before replying (script failed to load or to evaluate — e.g. a browser
 *   without module workers: Firefox 111-113 are inside the supported matrix and gained
 *   module workers in 114, BCD `api.Worker.Worker.ecmascript_modules`), or `postMessage`
 *   threw.
 * - `timeout`: no reply within `WORKER_SCOPE_TIMEOUT_MS`.
 * - `malformed`: the reply was not the expected shape, or could not be deserialised.
 * - `released`: `releaseShared()` ended the collection while the worker was running.
 *
 * Only the `state` reaches the wire (`index.ts`, `unwrapForWire`); the reason is for the
 * tests and the harness. A blocked worker is a legitimate configuration, and a missing
 * snapshot is not evidence of anything.
 *
 * ## Resources
 *
 * The worker is terminated on the reply, on timeout, on error, and in `releaseShared()`
 * (registered with `onRelease`). Whichever comes first settles the probe; the rest are
 * no-ops.
 */
export function workerScope(): Promise<ProbeResult<WorkerScopeValue>> {
    if (typeof Worker !== 'function') {
        return Promise.resolve(unavailable<WorkerScopeValue>('no-worker'));
    }

    return new Promise((resolve) => {
        const started = nowMs();
        let worker: Worker | null = null;
        let timer: ReturnType<typeof setTimeout> | undefined;
        let unregister: (() => void) | undefined;
        let settled = false;

        const finish = (result: ProbeResult<WorkerScopeValue>): void => {
            if (settled) return;
            settled = true;
            if (timer !== undefined) clearTimeout(timer);
            unregister?.();
            try {
                worker?.terminate();
            } catch {
                /* a worker that cannot be terminated is already gone */
            }
            resolve(result);
        };

        try {
            try {
                worker = createScopeWorker();
            } catch {
                finish(unavailable('blocked'));
                return;
            }

            unregister = onRelease(() => finish(unavailable('released')));

            worker.addEventListener('message', (event: MessageEvent) => {
                // First: a reply that arrives after the probe settled (timeout, release) must
                // not read the window snapshot, which would recreate the shared WebGL context
                // that `releaseShared()` has just lost.
                if (settled) return;
                const fromWorker = sanitiseReply(event.data);
                if (!fromWorker) {
                    finish(unavailable('malformed'));
                    return;
                }
                const elapsedMs = Math.round((nowMs() - started) * 1000) / 1000;
                const fromWindow = scopeSnapshot(unmaskedWebGl(sharedWebGl()?.context), windowCanvasHash());
                finish(ok({ workerType: 'dedicated', window: fromWindow, worker: fromWorker, elapsedMs }));
            });
            worker.addEventListener('messageerror', () => finish(unavailable('malformed')));
            worker.addEventListener('error', (event: Event) => {
                // Handled here; without this the engine also reports it as uncaught.
                event.preventDefault();
                finish(unavailable('blocked'));
            });

            timer = setTimeout(() => finish(unavailable('timeout')), WORKER_SCOPE_TIMEOUT_MS);

            try {
                worker.postMessage('scope');
            } catch {
                finish(unavailable('blocked'));
            }
        } catch (error) {
            // Nothing above is expected to throw outside its own guard; if something does,
            // the probe still settles, as an error, and the worker is still terminated.
            finish(failed(error));
        }
    });
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
            supportsOffscreen: typeof OffscreenCanvas === 'function',
            // From the collection's single shared context, not a throwaway one.
            supportsWebgl2: sharedWebGl()?.webgl2 ?? false,
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
                    // `islamic-umalqura` rather than bare `islamic`: Firefox logs a
                    // console warning for the unspecified variant on every run.
                    return ['gregory', 'buddhist', 'japanese', 'islamic-umalqura', 'hebrew', 'persian',
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
                // and any offset that was faked without checking DST. No formatted
                // "short" name: with `timeZoneName` as the only option ECMA-402 still
                // prints the date, so that string changed every day.
                try {
                    return {
                        name: resolved.timeZone,
                        offset: new Date().getTimezoneOffset(),
                        januaryOffset: new Date('2024-01-15T12:00:00Z').getTimezoneOffset(),
                        julyOffset: new Date('2024-07-15T12:00:00Z').getTimezoneOffset(),
                    };
                } catch (error) {
                    return { error: error instanceof Error ? error.name : 'Error' };
                }
            })(),
        };
    });
}

/**
 * `tier2.timezoneLmt` on the wire: ONLY the verdict.
 *
 * The two raw 1113 offsets are computed and compared here and never sent (five-review round,
 * privacy): when they disagree, the `Date` engine's offset is the visitor's REAL zone's Local
 * Mean Time, which is the location an `Intl`-only spoof was put there to hide. The server
 * rule `tz_intl_vs_date` needs the disagreement, not the place.
 */
export interface TimezoneLmtValue {
    /** The `Date` engine's 1113 offset equals `Intl`'s for its resolved zone; null when `Intl` could not compute one. */
    readonly agree: boolean | null;
}

/** Collapse -0 to 0 so a UTC zone is not canonicalised as `d:-0`. */
const noNegativeZero = (value: number): number => (value === 0 ? 0 : value);

/**
 * The time zone as the `Date` engine sees it, versus the time zone `Intl` claims. Sync,
 * TIER.TWO; the cost is one `DateTimeFormat` construction.
 *
 * ## Why the year 1113
 *
 * Before standard time, the tz database's offset for a zone is its city's Local Mean Time,
 * which follows longitude to the second: on 1 July 1113 Europe/Amsterdam is +00:17:30,
 * America/New_York −04:56:02, Asia/Kolkata +05:53:28 (measured below). Today's offsets are
 * shared by dozens of zones; 1113's nearly never are. So the two numbers below agree only
 * when the `Date` engine and `Intl` are running in the SAME zone.
 *
 * - `systemOffset` reads the engine's local zone through the `Date` constructor
 *   (local midnight versus UTC midnight). It is what the operating system's zone gives the
 *   JavaScript engine.
 * - `intlOffset` asks `Intl.DateTimeFormat` for the wall time of 1113-07-01T00:00Z in the zone
 *   `Intl` resolves to, and converts it back to an offset.
 *
 * Spoofing only `Intl` (`resolvedOptions().timeZone`, the common extension technique) leaves
 * the engine's `Date` in the real zone, and the two disagree. CreepJS reads the same idea as
 * `locationMeasured` (catalogue §12); here the client compares the pair and sends only
 * `agree` (the raw offsets would name the real zone), and the server rule `tz_intl_vs_date`
 * decides.
 *
 * ## Exact, not tolerant
 *
 * Measured on 2026-10-05 in Chromium 153, Firefox 155 and WebKit 26.6 for Europe/Amsterdam,
 * America/New_York and Asia/Kolkata (Playwright time-zone emulation): both numbers were equal
 * to the last bit in every engine and zone (17.5, −296.0333…, 353.4666…). No engine rounded,
 * so `agree` is strict equality and no tolerance was introduced.
 *
 * A time zone is a place, not a device (notes/15 §1): this is a consistency signal only and
 * the server keeps it out of both keys. It reports nothing the `intl` probe does not already
 * reveal about the zone.
 */
export function timezoneLmt(): ProbeResult<TimezoneLmtValue> {
    return probe('timezoneLmt', () => {
        const systemOffset = noNegativeZero((new Date(1113, 6, 1, 0, 0, 0).getTime() - Date.UTC(1113, 6, 1)) / -60000);
        if (!Number.isFinite(systemOffset)) throw new RangeError('no 1113 offset');

        let intlOffset: number | null = null;
        try {
            const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
            const instant = Date.UTC(1113, 6, 1);
            const format = new Intl.DateTimeFormat('en-US', {
                timeZone: zone,
                hourCycle: 'h23',
                year: 'numeric',
                month: 'numeric',
                day: 'numeric',
                hour: 'numeric',
                minute: 'numeric',
                second: 'numeric',
            });
            const parts: Record<string, number> = {};
            for (const part of format.formatToParts(instant)) {
                if (part.type !== 'literal') parts[part.type] = Number(part.value);
            }
            const wall = Date.UTC(
                parts.year as number, (parts.month as number) - 1, parts.day as number,
                parts.hour as number, parts.minute as number, parts.second as number,
            );
            intlOffset = Number.isFinite(wall) ? noNegativeZero((wall - instant) / 60000) : null;
        } catch {
            intlOffset = null;
        }

        return { agree: intlOffset === null ? null : systemOffset === intlOffset };
    });
}

/**
 * The offline-render audio sum. 2-4 ms.
 *
 * An oscillator through a DynamicsCompressor in an OfflineAudioContext, summed over a
 * fixed window. `OfflineAudioContext` never touches the OS audio stack, so this is an
 * ENGINE constant (measured on one machine: Chromium 124.043..., Firefox 35.749...),
 * useful as an engine cross-check and randomised per session by Brave and Firefox's
 * fingerprinting protection. It is not a device signal.
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
 * Settle `pending` within `ms`, as `unavailable('timeout')` if it has not settled by then.
 *
 * A probe whose promise never settles would stall `runDeferred`, and with it the whole
 * tier-2 envelope, so every probe that waits on the engine (an offline render, a layout-map
 * query, worker replies) is bounded. The timer is always cleared.
 */
export function withTimeout<T>(pending: Promise<ProbeResult<T>>, ms: number): Promise<ProbeResult<T>> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<ProbeResult<T>>((resolve) => {
        timer = setTimeout(() => resolve(unavailable('timeout')), ms);
    });

    return Promise.race([pending, timeout]).finally(() => {
        if (timer !== undefined) clearTimeout(timer);
    });
}

/** How long `audioReadback` waits for its renders before reporting `timeout`. */
export const AUDIO_READBACK_TIMEOUT_MS = 1000;

/** `tier2.audioReadback` on the wire. */
export interface AudioReadbackValue {
    /** Every sample of `getChannelData(0)` is exactly 0.25. */
    readonly constantExact: boolean;
    /** `copyFromChannel` returned the same samples as `getChannelData`, index by index. */
    readonly methodsAgree: boolean;
    /** Distinct sample values in `getChannelData(0)`; 1 on an unmodified engine. */
    readonly distinct: number;
    /** A 0 Hz oscillator rendered 128 samples of exactly 0. Null when it could not be run. */
    readonly silenceExact: boolean | null;
    /** A fresh `AnalyserNode` on a silent context reads -Infinity in every bin. */
    readonly analyserSilent: boolean | null;
    /** 0.37 written at 300, 900 and 1500 reads back there, and only there, through both methods. */
    readonly trapSurvives: boolean | null;
}

/** Run one optional audio sub-check: its boolean, or null when it threw or rejected. */
async function audioCheck(check: () => Promise<boolean> | boolean): Promise<boolean | null> {
    try {
        return await check();
    } catch {
        return null;
    }
}

/** The indices and values `trapSurvives` writes. Float32-rounded once, so the compare is exact. */
const AUDIO_TRAP_INDICES = [300, 900, 1500] as const;
const AUDIO_TRAP_VALUE = Math.fround(0.37);

/** Exactly the trap indices are non-zero, and each holds the trap value. */
function trapIntact(samples: Float32Array): boolean {
    let nonZero = 0;
    for (let index = 0; index < samples.length; index++) {
        if (samples[index] !== 0) nonZero++;
    }

    return nonZero === AUDIO_TRAP_INDICES.length && AUDIO_TRAP_INDICES.every((index) => samples[index] === AUDIO_TRAP_VALUE);
}

/**
 * Audio read-back exactness, against values the specification FIXES. Four checks, all
 * table-free; the per-engine cost is printed by tests/Browser/transport-checks.mjs.
 *
 * 1. `constantExact` / `methodsAgree` / `distinct`. An `OfflineAudioContext(1, 256, 44100)`
 *    renders a `ConstantSourceNode` whose `offset` is 0.25, straight to the destination.
 *    Web Audio defines the node's output as its `offset`, unity gain to the destination, so
 *    every sample must be 0.25 — exactly representable in Float32, so the compare is exact.
 *    The samples are read through `getChannelData` and `copyFromChannel`, which must agree.
 * 2. `silenceExact`. A 0 Hz `OscillatorNode` (a sine whose phase never advances) rendered
 *    for 128 frames must be exactly 0 everywhere. CreepJS `hasFakeAudio()` (catalogue §7).
 * 3. `analyserSilent`. A fresh `AnalyserNode` on a silent context has no input energy, so
 *    `getFloatFrequencyData` must be -Infinity dB in every bin. CreepJS uses this to detect
 *    Brave's strict farbling (catalogue §0, §7), which fills the bins with noise.
 * 4. `trapSurvives`. A 2000-frame `AudioBuffer` receives 0.37 at three indices through
 *    `copyToChannel`; read back through `copyFromChannel` AND `getChannelData`, exactly
 *    those three samples must be non-zero and equal to the written value. CreepJS's "noise
 *    factor" (catalogue §7) with a fixed rather than random trap, so the result is a stable
 *    boolean: noise on any read path changes the zeros, or the trap, or both.
 *
 * Measured on 2026-10-05 in Chromium 153, Firefox 155 and WebKit 26.6: all four hold
 * exactly in every engine (scratch measurement, then the harness).
 *
 * What breaks them: multiplicative or additive noise on the read-back path — Brave's audio
 * farbling, and fingerprint-randomising extensions that wrap `getChannelData`,
 * `copyFromChannel` or `getFloatFrequencyData` — makes samples differ from the specified
 * value, and a wrapper on only one read method makes the methods disagree.
 *
 * Why this is not CreepJS's audio module: that module compares a rendered sum with a frozen
 * table of known sums (catalogue §7), which ages with every engine release (notes/21 §2,
 * "Do not copy"). A value the specification fixes does not age. `audioOffline` stays as the
 * engine signal; this is the noise detector it cannot be.
 *
 * A VALUE probe, not an integrity finding: the server decides what a non-exact read-back
 * means (a privacy protection is not tampering by itself). The three newer checks are
 * individually optional: an engine without the API, or a check that throws, reports null
 * for that check and does not take the others down. The whole probe is bounded by
 * `AUDIO_READBACK_TIMEOUT_MS`, because an offline render can stall in a background tab in
 * some engines and a probe must always settle.
 */
export function audioReadback(): Promise<ProbeResult<AudioReadbackValue>> {
    const OfflineCtor = (typeof window === 'undefined'
        ? undefined
        : window.OfflineAudioContext ??
          (window as unknown as { webkitOfflineAudioContext?: typeof OfflineAudioContext }).webkitOfflineAudioContext) as
        | typeof OfflineAudioContext
        | undefined;
    if (typeof OfflineCtor !== 'function' || typeof ConstantSourceNode !== 'function') {
        return Promise.resolve(unavailable<AudioReadbackValue>('no-offline-audio'));
    }

    const constant = async (): Promise<Pick<AudioReadbackValue, 'constantExact' | 'methodsAgree' | 'distinct'>> => {
        const context = new OfflineCtor(1, 256, 44100);
        const source = context.createConstantSource();
        source.offset.value = 0.25;
        source.connect(context.destination);
        source.start(0);

        const buffer = await context.startRendering();
        const direct = buffer.getChannelData(0);
        const copied = new Float32Array(buffer.length);
        buffer.copyFromChannel(copied, 0);

        let constantExact = direct.length === 256;
        let methodsAgree = copied.length === direct.length;
        for (let index = 0; index < direct.length; index++) {
            const sample = direct[index] as number;
            if (sample !== 0.25) constantExact = false;
            if (!Object.is(sample, copied[index])) methodsAgree = false;
        }

        return { constantExact, methodsAgree, distinct: new Set(direct).size };
    };

    const silence = async (): Promise<boolean> => {
        const context = new OfflineCtor(1, 128, 44100);
        const oscillator = context.createOscillator();
        oscillator.frequency.value = 0;
        oscillator.connect(context.destination);
        oscillator.start(0);
        const samples = (await context.startRendering()).getChannelData(0);

        return samples.length === 128 && samples.every((sample) => sample === 0);
    };

    const analyser = (): boolean => {
        const node = new OfflineCtor(1, 1, 44100).createAnalyser();
        const bins = new Float32Array(node.frequencyBinCount);
        node.getFloatFrequencyData(bins);

        return bins.length > 0 && bins.every((value) => value === -Infinity);
    };

    const trap = (): boolean => {
        if (typeof AudioBuffer !== 'function') throw new Error('no AudioBuffer constructor');
        const buffer = new AudioBuffer({ length: 2000, sampleRate: 44100 });
        for (const index of AUDIO_TRAP_INDICES) {
            buffer.copyToChannel(Float32Array.of(AUDIO_TRAP_VALUE), 0, index);
        }
        const copied = new Float32Array(buffer.length);
        buffer.copyFromChannel(copied, 0);

        return trapIntact(copied) && trapIntact(buffer.getChannelData(0));
    };

    const render = probeAsync('audioReadback', async (): Promise<AudioReadbackValue> => {
        const [core, silenceExact, analyserSilent, trapSurvives] = await Promise.all([
            constant(),
            audioCheck(silence),
            audioCheck(analyser),
            audioCheck(trap),
        ]);

        return { ...core, silenceExact, analyserSilent, trapSurvives };
    });

    return withTimeout(render, AUDIO_READBACK_TIMEOUT_MS);
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
// TIER HARDWARE - engine-independent device/OS signals, deferred after tier 2
// =====================================================================

/**
 * Installed-font signature by advance widths, names discarded.
 *
 * Each family is tried against the three generic fallbacks at 48px; a family is
 * present when its width differs from the generic's. For each present family the
 * rounded widths of two fixed strings form a pair, and the SORTED, DE-DUPLICATED pair
 * list is the value. Pairs survive a browser switch because the same OS font file
 * yields the same advance widths in every engine (measured: identical pairs in
 * Chromium, Firefox and WebKit on one machine, apart from families that only
 * Chromium's fontconfig aliasing resolves). Emoji fonts are deliberately not probed:
 * bitmap fonts measure differently per engine, and `emojiMetrics` covers them.
 *
 * Cost: 3-7 ms warm, 40-130 ms cold (first font matching in the renderer) — the single
 * most expensive synchronous probe (round-2 BR2-1: 69 / 173 / 294 ms cold in Chromium /
 * Firefox / WebKit). So it is a STEPPED probe: `fontMetricsSteps()` measures the families in
 * `FONT_METRICS_STEPS` chunks on ONE canvas, and the scheduler (`runDeferred`) runs each
 * chunk in its own idle slice. `fontMetrics()` runs every step at once and is the same
 * measurement: the value is a pure function of the families, not of when they were measured
 * nor of how they are chunked (the pairs are a sorted set and `count` a sum).
 */
export function fontMetrics(): ProbeResult<FontMetricsValue> {
    return probe('fontMetrics', () => runSteps(fontMetricsSteps()));
}

/** `tier2.fontMetrics` on the wire. */
export interface FontMetricsValue {
    readonly count: number;
    readonly pairs: string;
}

/** The families `fontMetrics` measures, in step order. */
export const FONT_METRICS_FAMILIES: readonly string[] = [
    // Windows
    'Arial', 'Arial Black', 'Bahnschrift', 'Calibri', 'Cambria', 'Candara', 'Comic Sans MS',
    'Consolas', 'Constantia', 'Corbel', 'Courier New', 'Franklin Gothic Medium', 'Georgia',
    'Impact', 'Lucida Console', 'Malgun Gothic', 'Microsoft YaHei', 'MS Gothic',
    'Palatino Linotype', 'Segoe UI', 'Segoe UI Variable', 'SimSun', 'Tahoma',
    'Times New Roman', 'Trebuchet MS', 'Verdana', 'Yu Gothic',
    // macOS / iOS
    'American Typewriter', 'Avenir', 'Baskerville', 'Futura', 'Geneva', 'Gill Sans',
    'Helvetica', 'Helvetica Neue', 'Hoefler Text', 'Lucida Grande', 'Menlo', 'Monaco',
    'Optima', 'PingFang SC', 'San Francisco', 'SF Pro',
    // Linux
    'Cantarell', 'DejaVu Sans', 'DejaVu Sans Mono', 'DejaVu Serif', 'FreeMono', 'FreeSans',
    'FreeSerif', 'Liberation Mono', 'Liberation Sans', 'Liberation Serif', 'Noto Sans',
    'Noto Sans CJK JP', 'Ubuntu', 'Ubuntu Mono',
    // Android and common installs
    'Droid Sans', 'Fira Code', 'Inter', 'JetBrains Mono', 'Open Sans', 'Roboto', 'Source Code Pro',
];

/**
 * How many idle slices `fontMetrics` is spread over. Three in decision G-D5i; six since round-3
 * CL3-5: at 4x CPU throttling (a mid-range phone) the chunk holding the machine's own OS
 * families measured 98-121 ms, one long task each time.
 */
export const FONT_METRICS_STEPS = 6;

/**
 * The families of each step: dealt round-robin (family `i` to step `i % FONT_METRICS_STEPS`),
 * not cut into consecutive runs. The list is grouped by OS, and the expensive part of a step is
 * the first match of fonts that EXIST (a family that is absent costs a cheap failed lookup),
 * so consecutive runs put all of one machine's own families into one or two steps. Dealt out,
 * every step gets a share of every OS's families.
 */
export function fontMetricsChunks(): string[][] {
    const chunks: string[][] = Array.from({ length: FONT_METRICS_STEPS }, () => []);
    FONT_METRICS_FAMILIES.forEach((family, index) => {
        (chunks[index % FONT_METRICS_STEPS] as string[]).push(family);
    });

    return chunks;
}

/**
 * `fontMetrics` as steps for the scheduler. The canvas, the generic base widths and the
 * accumulators live in the closure; each step measures one chunk of families against them.
 * Throws (so the probe is `error`) only where there is no 2D context at all.
 */
export function fontMetricsSteps(): ProbeSteps<FontMetricsValue> {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    if (!context) throw new Error('no 2d context');

    const T1 = 'mmmmmmmmmmlliI1O0WwQ@';
    const T2 = 'The quick brown fox jumps over 1234567890';
    const generics = ['sans-serif', 'serif', 'monospace'];

    // Measured by the first step, not here: `fontMetricsSteps()` is called when the probe is
    // reached, and the first slice is where the first canvas work belongs.
    let base: Record<string, number> | null = null;
    const pairs = new Set<string>();
    let count = 0;

    const measure = (families: readonly string[]): void => {
        if (base === null) {
            base = {};
            for (const generic of generics) {
                context.font = `48px ${generic}`;
                base[generic] = context.measureText(T1).width;
            }
        }
        for (const family of families) {
            for (const generic of generics) {
                context.font = `48px "${family}", ${generic}`;
                const w1 = context.measureText(T1).width;
                if (Math.abs(w1 - (base[generic] as number)) > 0.01) {
                    count++;
                    pairs.add(`${Math.round(w1)}:${Math.round(context.measureText(T2).width)}`);
                    break;
                }
            }
        }
    };

    const steps = fontMetricsChunks().map((families) => (): void => measure(families));

    return { steps, result: () => ({ count, pairs: [...pairs].sort().join(',') }) };
}

/**
 * What `emojiMetrics` measures: 😀 (Emoji 1.0), 🏳️‍🌈 (a ZWJ flag sequence, Emoji 4.0) and
 * 👨‍👩‍👧 (a ZWJ family sequence, Emoji 2.0) — all in every OS emoji font this product meets.
 *
 * Until round-2 BR2-12 the string ended in 🫠 (U+1FAE0, Emoji 14.0, 2021). An OS emoji font
 * older than that has no glyph for it (Windows 10's Segoe UI Emoji, macOS before 12.3, older
 * Noto builds), and each ENGINE then fills the gap its own way — Firefox from the Twemoji
 * Mozilla font it bundles, Chromium and WebKit from system fallback or a .notdef box — so the
 * same device measured different widths in different browsers, which is the opposite of what
 * a cross-browser soft component is for. [EXT: the per-OS coverage is from the vendors' emoji
 * release notes; not measured on Windows here.] Measured on this Linux box with Noto Color
 * Emoji: each of the four glyphs 40 px in all three engines, so the old string was 160 and
 * this one is 120 in Chromium, Firefox and WebKit alike.
 *
 * `emojiMetrics` is a soft `tier2` component (DeviceComponents `emoji`), in no key: changing
 * the string re-keys nothing, it changes the one soft value once.
 */
export const EMOJI_SAMPLE = '😀🏳️‍🌈👨‍👩‍👧';

/**
 * Advance width of a ZWJ emoji string at 32px, rounded. Measures which emoji font
 * shaped the string (an OS- and font-version-level class, not a per-device value).
 *
 * The OS emoji fonts are named first (CONTRACT DEVIATION from "32px sans-serif",
 * recorded in the W1 report): with a bare `sans-serif`, WebKit on Linux takes the
 * monochrome U+1F600 from DejaVu Sans while Chromium and Firefox take Noto Color
 * Emoji, so the same machine measured 153 vs 160. Naming the emoji fonts first makes
 * every engine shape the string with the same font (measured 160 / 160 / 160 with the old
 * four-emoji string, 120 / 120 / 120 with `EMOJI_SAMPLE`).
 */
export function emojiMetrics(): ProbeResult<{ width: number }> {
    return probe('emojiMetrics', () => {
        const context = document.createElement('canvas').getContext('2d');
        if (!context) throw new Error('no 2d context');

        context.font = '32px "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif';
        return { width: Math.round(context.measureText(EMOJI_SAMPLE).width) };
    });
}

/**
 * Which writing scripts the OS can render, as a bit string.
 *
 * One sample character per script is measured at 48px sans-serif and compared with
 * the metrics of an unassigned code point (U+0378), which every font renders as its
 * .notdef box. A bit is 1 when any of width, ascent, descent, left or right differs
 * by more than half a pixel, i.e. a real glyph was found by font fallback.
 *
 * A STEPPED probe like `fontMetrics` (round-3 CL3-5): each sample is a font-fallback search,
 * and the sixteen together measured 80-102 ms at 4x CPU throttling, one long task. The
 * scheduler runs `scriptsSteps()` over `SCRIPTS_STEPS` idle slices; `scripts()` runs every
 * step at once. Same value either way: bit `i` is sample `i`'s, whichever step measured it.
 */
export function scripts(): ProbeResult<{ bits: string }> {
    return probe('scripts', () => runSteps(scriptsSteps()));
}

/** The script samples, in bit order: Arabic, Hebrew, Devanagari, Bengali, Tamil, Thai, Hangul, Hiragana, CJK, Armenian, Georgian, Ethiopic, Khmer, Tibetan, Sinhala, Myanmar. */
export const SCRIPT_SAMPLES: readonly string[] = [
    'ب', 'א', 'क', 'ক', 'க', 'ก', '가', 'あ',
    '中', 'Ա', 'ა', 'ሀ', 'ក', 'ཀ', 'අ', 'က',
];

/** How many idle slices `scripts` is spread over (four samples each). */
export const SCRIPTS_STEPS = 4;

/**
 * `scripts` as steps for the scheduler: one canvas, the .notdef reference measured by the
 * first step, and sample `i` measured by step `i % SCRIPTS_STEPS`. Throws (so the probe is
 * `error`) only where there is no 2D context at all.
 */
export function scriptsSteps(): ProbeSteps<{ bits: string }> {
    const context = document.createElement('canvas').getContext('2d');
    if (!context) throw new Error('no 2d context');
    context.font = '48px sans-serif';

    const metrics = (text: string): number[] => {
        const m = context.measureText(text);
        return [
            m.width,
            m.actualBoundingBoxAscent ?? 0,
            m.actualBoundingBoxDescent ?? 0,
            m.actualBoundingBoxLeft ?? 0,
            m.actualBoundingBoxRight ?? 0,
        ];
    };

    let notdef: number[] | null = null;
    const bits: Array<'0' | '1' | undefined> = SCRIPT_SAMPLES.map(() => undefined);

    const steps = Array.from({ length: SCRIPTS_STEPS }, (_, step) => (): void => {
        notdef ??= metrics('\u0378');
        const reference = notdef;
        SCRIPT_SAMPLES.forEach((sample, index) => {
            if (index % SCRIPTS_STEPS !== step) return;
            bits[index] = metrics(sample).some((v, i) => Math.abs(v - (reference[i] as number)) > 0.5) ? '1' : '0';
        });
    });

    return {
        steps,
        result: () => {
            if (bits.some((bit) => bit === undefined)) throw new Error('scripts: a step did not run');

            return { bits: bits.join('') };
        },
    };
}

/**
 * GPU identity: the WebGPU adapter when the engine exposes one, and the WebGL
 * vendor/renderer, shader precision and resource limits from the collection's single
 * shared context. The renderer string is also normalised to a model (ANGLE wrapper,
 * API names, driver versions and PCI ids stripped) so Chromium's and Firefox's spelling
 * of the same card can agree. 1-2 ms warm once the context exists.
 *
 * `mirroredParamsAgree` (CONTRACT-2 V4) compares the same limits read from a WebGL 1 and a
 * WebGL 2 context: see `mirroredParams`.
 */
export function gpu(): Promise<ProbeResult<Record<string, unknown>>> {
    return probeAsync('gpu', async () => {
        let webgpu: Record<string, unknown> | null = null;
        try {
            const adapter = await webgpuAdapter();
            if (adapter) {
                const info = (adapter as { info?: Partial<GPUAdapterInfo> & { isFallbackAdapter?: boolean } }).info;
                webgpu = {
                    vendor: info?.vendor ?? null,
                    architecture: info?.architecture ?? null,
                    device: info?.device ?? null,
                    description: info?.description ?? null,
                    // `GPUAdapterInfo.isFallbackAdapter` (Chrome 136, Firefox 141, Safari 26);
                    // the `GPUAdapter` member it replaced was removed in Chrome 140, so reading
                    // only that one gave `null` on every current Chromium (round-2 STD-25).
                    fallback: info?.isFallbackAdapter ?? (adapter as { isFallbackAdapter?: boolean }).isFallbackAdapter ?? null,
                };
            }
        } catch {
            webgpu = null;
        }

        let webgl: Record<string, unknown> | null = null;
        try {
            const shared = sharedWebGl();
            if (shared) {
                const gl = shared.context;
                const debug = gl.getExtension('WEBGL_debug_renderer_info');
                const vendor = String(debug ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR));
                const renderer = String(debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER));
                const precisionOf = (shader: number): string => {
                    const format = gl.getShaderPrecisionFormat(shader, gl.HIGH_FLOAT);
                    return format ? `${format.rangeMin},${format.rangeMax},${format.precision}` : 'none';
                };
                const limitNames = [
                    'MAX_TEXTURE_SIZE', 'MAX_RENDERBUFFER_SIZE', 'MAX_VERTEX_ATTRIBS',
                    'MAX_VERTEX_UNIFORM_VECTORS', 'MAX_FRAGMENT_UNIFORM_VECTORS', 'MAX_VARYING_VECTORS',
                    'MAX_TEXTURE_IMAGE_UNITS', 'MAX_COMBINED_TEXTURE_IMAGE_UNITS',
                ] as const;
                const limits: Record<string, number> = {};
                for (const name of limitNames) {
                    const value: unknown = gl.getParameter(gl[name]);
                    limits[name] = typeof value === 'number' ? value : -1;
                }

                webgl = {
                    vendor,
                    renderer,
                    model: normaliseRenderer(renderer),
                    precision: { frag: precisionOf(gl.FRAGMENT_SHADER), vert: precisionOf(gl.VERTEX_SHADER) },
                    limits,
                    extCount: (gl.getSupportedExtensions() ?? []).length,
                    webgl2: shared.webgl2,
                };
            }
        } catch {
            webgl = null;
        }

        let mirroredParamsAgree: boolean | null = null;
        try {
            mirroredParamsAgree = mirroredParams(sharedWebGl());
        } catch {
            mirroredParamsAgree = null;
        }

        return { webgpu, webgl, mirroredParamsAgree };
    });
}

/** The page's one `requestAdapter()` call, settled or in flight; `undefined` until first asked. */
let webgpuAdapterRequest: Promise<GPUAdapter | null> | undefined;

/**
 * The WebGPU adapter, asked for ONCE per page and remembered — a null result included.
 *
 * `navigator.gpu.requestAdapter()` on a machine without an adapter (VMs, remote desktops,
 * blocklisted GPUs, headless) makes Chromium print `warning: No available adapters.` to the
 * console on EVERY call; with one call per collection that was two lines per page load on
 * the admin demo and one per `measureProbes()` (round-2 BR2-7, 30 lines in a 30-collection
 * run). The adapter does not change while the page lives, so the first answer is the answer.
 * The first call on such a machine still logs once: the line is Chromium's, raised inside
 * `requestAdapter()` itself, and nothing on the page can tell beforehand whether an adapter
 * exists. Null where `navigator.gpu` is absent (Firefox outside Windows, WebKit) or the
 * request throws. Never rejects.
 */
export function webgpuAdapter(): Promise<GPUAdapter | null> {
    if (webgpuAdapterRequest === undefined) {
        webgpuAdapterRequest = (async (): Promise<GPUAdapter | null> => {
            try {
                // `navigator.gpu` is absent in Firefox (except Windows) and WebKit; `info`
                // is absent on older Chromium, hence the optional reads on a typed object.
                const gpuApi = 'gpu' in navigator ? (navigator.gpu as GPU | undefined) : undefined;
                if (!gpuApi || typeof gpuApi.requestAdapter !== 'function') return null;

                return (await gpuApi.requestAdapter()) ?? null;
            } catch {
                return null;
            }
        })();
    }

    return webgpuAdapterRequest;
}

/** Forget the remembered adapter, so the next `webgpuAdapter()` asks again. Tests only. */
export function resetWebgpuAdapterForTests(): void {
    webgpuAdapterRequest = undefined;
}

/** The parameters both WebGL versions must report identically (CONTRACT-2 V4). */
const MIRRORED_PARAMS = [
    'MAX_TEXTURE_SIZE', 'MAX_RENDERBUFFER_SIZE', 'MAX_VERTEX_ATTRIBS', 'MAX_VARYING_VECTORS',
    'MAX_COMBINED_TEXTURE_IMAGE_UNITS', 'ALIASED_POINT_SIZE_RANGE',
] as const;

/** One context's mirrored parameters plus its unmasked renderer, as one comparable string. */
function mirroredSignature(gl: WebGLRenderingContext | WebGL2RenderingContext): string {
    const values = MIRRORED_PARAMS.map((name) => {
        const value: unknown = gl.getParameter(gl[name]);
        return ArrayBuffer.isView(value) ? Array.from(value as unknown as ArrayLike<number>).join(',') : String(value);
    });
    values.push(String(unmaskedWebGl(gl).renderer));

    return values.join('|');
}

/**
 * WebGL 1 versus WebGL 2: the same GPU must report the same limits and the same unmasked
 * renderer through both APIs. A spoofer that patches `getParameter` on one context type
 * only (the common case: `WebGLRenderingContext.prototype`) makes them disagree. CreepJS's
 * mirrored-params check (catalogue §6) compares all of ~60 parameters minus three it found
 * legitimately different (`ALIASED_LINE_WIDTH_RANGE`, `SHADING_LANGUAGE_VERSION`, `VERSION`);
 * this compares the fixed short list of CONTRACT-2 V4.
 *
 * The other-version context is created on a fresh canvas here, only for this comparison, and
 * lost before returning, so the collection never holds more than one extra live context.
 * Null when there is no shared context, or when the other version cannot be created (WebGL 2
 * absent, or blocked): absence is not a disagreement.
 *
 * Measured on 2026-10-05: identical in Chromium 153 (SwiftShader) and WebKit 26.6;
 * Firefox 155 in this container has no WebGL at all, so null there.
 */
function mirroredParams(shared: SharedWebGl | null): boolean | null {
    if (!shared) return null;
    if (!shared.webgl2 && typeof WebGL2RenderingContext !== 'function') return null;

    const attributes: WebGLContextAttributes = { failIfMajorPerformanceCaveat: false };
    const canvas = document.createElement('canvas');
    const other = (shared.webgl2 ? canvas.getContext('webgl', attributes) : canvas.getContext('webgl2', attributes)) as
        | WebGLRenderingContext
        | WebGL2RenderingContext
        | null;
    if (!other) return null;

    try {
        return mirroredSignature(shared.context) === mirroredSignature(other);
    } finally {
        try {
            other.getExtension('WEBGL_lose_context')?.loseContext();
        } catch {
            /* a context that cannot be lost is left to the GC */
        }
    }
}

/** Strip the ANGLE wrapper, graphics-API names, driver versions and PCI ids from a renderer string. */
export function normaliseRenderer(renderer: string): string {
    return renderer
        .replace(/^ANGLE \((.*)\)$/, '$1')
        .replace(/\(?0x[0-9A-Fa-f]+\)?/g, ' ')
        .replace(/\b(Direct3D\d*|D3D\d*|OpenGL(?: ES)?|Vulkan|Metal|vs_\d_\d|ps_\d_\d|PCIe|SSE2)\b/g, ' ')
        .replace(/\b\d+\.\d+(\.\d+)*\b/g, ' ')
        .replace(/[,()/]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .toLowerCase();
}

/**
 * The OS audio output path: sample rate and channel count of the default device, from the
 * collection's shared `AudioContext`. A `maxChannelCount` of 0 means no output device is
 * present (the server treats the component as absent then, not as "0 channels").
 *
 * No `baseLatencyBucket` (round-2 BR2-2): it was a per-engine constant (10 / 0 / 3 ms in
 * Chromium / Firefox / WebKit on one machine) that no server rule read, and a latency is an
 * estimate of the output path, not a property of the device.
 */
export function audioHardware(): ProbeResult<{ sampleRate: number; maxChannelCount: number }> {
    return probe('audioHardware', () => {
        const context = sharedAudioContext();
        if (!context) throw new Error('no AudioContext');

        return {
            sampleRate: context.sampleRate,
            maxChannelCount: context.destination.maxChannelCount,
        };
    });
}

/**
 * Hardware decoding of the three mainstream codecs at 1080p30, as `supported`,
 * `smooth`, `powerEfficient` bits. `powerEfficient` is the hardware-decoder signal.
 */
export function decoders(): Promise<ProbeResult<{ h264: string; vp9: string; av1: string }>> {
    return probeAsync('decoders', async () => {
        const capabilities = navigator.mediaCapabilities;
        if (!capabilities || typeof capabilities.decodingInfo !== 'function') {
            throw new Error('no mediaCapabilities');
        }

        const query = async (contentType: string): Promise<string> => {
            try {
                const info = await capabilities.decodingInfo({
                    type: 'file',
                    video: { contentType, width: 1920, height: 1080, bitrate: 4_000_000, framerate: 30 },
                });
                return `${info.supported ? 1 : 0}${info.smooth ? 1 : 0}${info.powerEfficient ? 1 : 0}`;
            } catch {
                return 'err';
            }
        };

        const [h264, vp9, av1] = await Promise.all([
            query('video/mp4; codecs="avc1.42E01E"'),
            query('video/webm; codecs="vp09.00.10.08"'),
            query('video/mp4; codecs="av01.0.05M.08"'),
        ]);

        return { h264, vp9, av1 };
    });
}

/** How long `voices` waits for `voiceschanged` when the first `getVoices()` is empty. */
export const VOICES_WAIT_MS = 300;

/**
 * Speech-synthesis voices: a count, and a keyed-later hash of the OS-installed names.
 * Chrome's cloud voices (names starting with "Google") are excluded, since they are
 * not a property of the device. Waits at most `VOICES_WAIT_MS` for `voiceschanged`.
 *
 * An EMPTY list is `unavailable`, never a value (round-2 BR2-4 / STD-26): "no speech
 * backend", "voices not loaded within the wait" and "this engine lists none" are not one
 * fact about the device, and the hash of nothing (`811c9dc5:0`) was scored as two devices
 * AGREEING on a default. `empty` is a list that was there and had no entries; `timeout` is
 * a list that never arrived. Only the state reaches the wire.
 *
 * The `voiceschanged` listener is removed on every path (round-2 PERF-22): `{ once: true }`
 * only removes it when the event fires, so the timeout path leaked one listener per
 * collection (13 → 42 over 30 collections on a page without voices).
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
                    if (timer !== undefined) clearTimeout(timer);
                    try {
                        synth.removeEventListener('voiceschanged', onChange);
                    } catch {
                        /* a target that cannot remove has nothing registered */
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

        const osNames = list.map((voice) => voice.name).filter((name) => !name.startsWith('Google')).sort();

        return ok({ count: list.length, osCount: osNames.length, osHash: fnv1a32(osNames.join('|')) });
    })();
}

/** `tier2.gpuMath` on the wire. */
export interface GpuMathValue {
    /** `fnv1a32` of the 64 RGBA bytes of the 4×4 render. */
    readonly hash: string;
    /** The fragment-shader precision the render ran at, e.g. `highp:23`; compare hashes only within one class. */
    readonly precision: string;
    /** The renderer names a software rasteriser; the server then marks the component absent. */
    readonly software: boolean;
}

/** Renderer strings of software rasterisers (SwiftShader, llvmpipe, softpipe, WARP / Basic Render, lavapipe, Mesa's software paths). */
const SOFTWARE_RENDERER = /swiftshader|llvmpipe|softpipe|lavapipe|\bwarp\b|basic render|software rasterizer|mesa offscreen/i;

/** Whether a renderer string names a software rasteriser. */
export function isSoftwareRenderer(renderer: string): boolean {
    return SOFTWARE_RENDERER.test(renderer);
}

const GPU_MATH_VERTEX = 'attribute vec2 p; void main() { gl_Position = vec4(p, 0.0, 1.0); }';

/**
 * Four channels of amplified transcendental output, each varying in BOTH coordinates
 * (notes/22 review: at 8 bits only an amplified, two-dimensional function carries bits).
 */
const GPU_MATH_FRAGMENT = `
#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif
void main() {
    float x = gl_FragCoord.x / 4.0;
    float y = gl_FragCoord.y / 4.0;
    gl_FragColor = vec4(
        fract(sin(x * 7.0 + y * 3.0) * 43758.5453),
        fract(exp(x * 3.0 + y) * 1013.0),
        fract(pow(x + 0.5, 2.2 + y) * 611.0),
        fract(log(x + y + 1.5) * 997.0)
    );
}`;

/** Thrown inside the render to settle the probe as `unavailable(reason)`. Never on the wire. */
class GpuMathUnavailable extends Error {
    constructor(readonly reason: string) {
        super(reason);
    }
}

/**
 * The GPU's transcendental arithmetic, read back as pixels (notes/22 M1). TIER.HARDWARE, on
 * the collection's shared WebGL context.
 *
 * `Math.sin/exp/pow/log` in JavaScript identify the ENGINE (`mathDual`). The same functions
 * in a fragment shader run on the GPU — or ANGLE's translation of it, or a software
 * rasteriser — whose implementations differ per vendor, driver generation and backend in the
 * low mantissa bits. A 4×4 render whose four channels carry amplified `sin`, `exp`, `pow` and
 * `log` of both pixel coordinates is read back as 64 bytes and hashed.
 *
 * The review's REQUIRED CHANGES (notes/22), all applied:
 * - every channel amplified and varying in both coordinates (the design's `exp/pow/log`
 *   channels carried no bits at 8 bits);
 * - read twice: two reads that differ are a randomised read-back → `unavailable('randomised')`;
 * - `software`: true when the renderer names a software rasteriser. SwiftShader and llvmpipe
 *   produce one value for a whole population, so the server marks the component absent then;
 *   the hash is still reported. Brave/RFP are excluded on the server through `resistance`;
 * - `WebGL2RenderingContext.readPixels/getParameter/getExtension` added to the lie targets
 *   (phantom.ts), since the shared context is WebGL 2 where available.
 *
 * Measured by the review (Linux VM, no GPU): stable 9/9 in every configuration; the same
 * driver gave the same hash through Chromium, Firefox and WebKit; a different backend changed
 * it. Cold 3-30 ms (shader compile + first draw), warm ≤ 2 ms; this implementation's cost is
 * printed by tests/Browser/transport-checks.mjs. Real GPUs are UNVERIFIED.
 *
 * Privacy: it re-identifies the GPU that WebKit ("Apple GPU") and Firefox deliberately report
 * coarsely, so it is a soft, agree-only component behind the consent gate.
 *
 * Mechanics: the render goes to a private 4×4 RGBA8 framebuffer, not to the shared canvas,
 * with dithering disabled (dithering would perturb 8-bit writes), and every object created is
 * deleted and the framebuffer, program, buffer and dither state restored afterwards, so the
 * shared context is left as other probes expect it. `unavailable`: `no-webgl`,
 * `compile-failed`, `incomplete-framebuffer`, `randomised`.
 */
export function gpuMath(): ProbeResult<GpuMathValue> {
    try {
        return ok(renderGpuMath());
    } catch (error) {
        return error instanceof GpuMathUnavailable ? unavailable(error.reason) : failed(error);
    }
}

/** The render behind `gpuMath`. Throws `GpuMathUnavailable` for the expected failures. */
function renderGpuMath(): GpuMathValue {
    const shared = sharedWebGl();
    if (!shared) throw new GpuMathUnavailable('no-webgl');
    const gl = shared.context;

    const highp = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);
    const precision = highp && highp.precision > 0
        ? `highp:${highp.precision}`
        : `mediump:${gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT)?.precision ?? 0}`;
    const identity = unmaskedWebGl(gl);
    const renderer = identity.renderer ?? String(gl.getParameter(gl.RENDERER));

    const created: Array<() => void> = [];
    const ditherWas = gl.isEnabled(gl.DITHER);
    const previousFramebuffer = gl.getParameter(gl.FRAMEBUFFER_BINDING) as WebGLFramebuffer | null;
    const previousProgram = gl.getParameter(gl.CURRENT_PROGRAM) as WebGLProgram | null;
    const previousBuffer = gl.getParameter(gl.ARRAY_BUFFER_BINDING) as WebGLBuffer | null;
    const previousTexture = gl.getParameter(gl.TEXTURE_BINDING_2D) as WebGLTexture | null;
    const previousViewport = gl.getParameter(gl.VIEWPORT) as Int32Array | null;
    let attribute = -1;

    try {
        const compile = (type: number, source: string): WebGLShader => {
            const shader = gl.createShader(type);
            if (!shader) throw new GpuMathUnavailable('compile-failed');
            created.push(() => gl.deleteShader(shader));
            gl.shaderSource(shader, source);
            gl.compileShader(shader);
            if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new GpuMathUnavailable('compile-failed');
            return shader;
        };
        const program = gl.createProgram();
        if (!program) throw new GpuMathUnavailable('compile-failed');
        created.push(() => gl.deleteProgram(program));
        gl.attachShader(program, compile(gl.VERTEX_SHADER, GPU_MATH_VERTEX));
        gl.attachShader(program, compile(gl.FRAGMENT_SHADER, GPU_MATH_FRAGMENT));
        gl.linkProgram(program);
        if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new GpuMathUnavailable('compile-failed');

        const texture = gl.createTexture();
        const framebuffer = gl.createFramebuffer();
        const buffer = gl.createBuffer();
        if (!texture || !framebuffer || !buffer) throw new GpuMathUnavailable('incomplete-framebuffer');
        created.push(() => gl.deleteTexture(texture), () => gl.deleteFramebuffer(framebuffer), () => gl.deleteBuffer(buffer));

        gl.bindTexture(gl.TEXTURE_2D, texture);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 4, 4, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
        gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
        gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, texture, 0);
        if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) throw new GpuMathUnavailable('incomplete-framebuffer');

        gl.disable(gl.DITHER);
        gl.viewport(0, 0, 4, 4);
        gl.useProgram(program);
        gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
        attribute = gl.getAttribLocation(program, 'p');
        gl.enableVertexAttribArray(attribute);
        gl.vertexAttribPointer(attribute, 2, gl.FLOAT, false, 0, 0);
        gl.drawArrays(gl.TRIANGLES, 0, 3);

        const first = new Uint8Array(64);
        const second = new Uint8Array(64);
        gl.readPixels(0, 0, 4, 4, gl.RGBA, gl.UNSIGNED_BYTE, first);
        gl.readPixels(0, 0, 4, 4, gl.RGBA, gl.UNSIGNED_BYTE, second);
        for (let i = 0; i < 64; i++) {
            if (first[i] !== second[i]) throw new GpuMathUnavailable('randomised');
        }

        return { hash: fnv1a32Bytes(first), precision, software: isSoftwareRenderer(renderer) };
    } finally {
        try {
            if (attribute >= 0) gl.disableVertexAttribArray(attribute);
            if (ditherWas) gl.enable(gl.DITHER);
            gl.bindFramebuffer(gl.FRAMEBUFFER, previousFramebuffer);
            gl.useProgram(previousProgram);
            gl.bindBuffer(gl.ARRAY_BUFFER, previousBuffer);
            gl.bindTexture(gl.TEXTURE_2D, previousTexture);
            if (previousViewport && previousViewport.length === 4) {
                gl.viewport(previousViewport[0] as number, previousViewport[1] as number, previousViewport[2] as number, previousViewport[3] as number);
            }
        } catch {
            /* a lost context has no state left to restore */
        }
        for (const dispose of created.reverse()) {
            try {
                dispose();
            } catch {
                /* already gone with the context */
            }
        }
    }
}

/** The OS-indicative families `fontFaces` checks, in wire order (CONTRACT-2 V3). */
export const FONT_FACE_FAMILIES = {
    windows: ['Segoe UI', 'Segoe UI Emoji', 'Calibri', 'Cambria', 'Consolas', 'Tahoma', 'MS UI Gothic', 'Bahnschrift', 'Segoe Fluent Icons', 'Ink Free'],
    mac: ['Helvetica Neue', 'Menlo', 'Monaco', 'Geneva', 'Avenir Next', 'SF Pro', 'Apple Color Emoji', 'PingFang SC', 'Hiragino Sans', 'Baskerville'],
    linux: ['DejaVu Sans', 'Liberation Sans', 'Noto Color Emoji', 'Ubuntu', 'Cantarell', 'Nimbus Sans'],
    android: ['Roboto', 'Noto Sans CJK JP', 'Droid Sans Mono'],
    chromeos: ['Google Sans'],
} as const;

/** The family the honesty gate asks for; no system has it. */
export const FONT_FACE_SENTINEL = 'nc-no-such-font-7f3a';

/**
 * `tier2.fontFaces` on the wire: counts only. The per-family bit string was dropped
 * (five-review round): the server reads only the per-OS counts, and the bits identified the
 * exact installed set.
 */
export interface FontFacesValue {
    /** Families found, over all `FONT_FACE_FAMILIES` (ChromeOS's included). */
    readonly count: number;
    readonly windows: number;
    readonly mac: number;
    readonly linux: number;
    readonly android: number;
}

/** How long `fontFaces` waits for all its `FontFace.load()` calls. */
export const FONT_FACES_TIMEOUT_MS = 2000;

/** Whether `new FontFace(family, 'local("family")').load()` fulfils, i.e. the system has it. */
async function hasLocalFont(FontFaceCtor: typeof FontFace, family: string): Promise<boolean> {
    const face = new FontFaceCtor(family, `local("${family}")`);
    try {
        await face.load();
        return true;
    } catch {
        return false;
    }
}

/**
 * Which OS-indicative font families are installed, from `FontFace` `local()` loads.
 * TIER.HARDWARE.
 *
 * The server compares the per-OS counts with the OS the User-Agent claims (`fonts_vs_ua_os`):
 * a "Windows" visitor with no Windows font and five macOS ones is not on Windows.
 *
 * ## Method: `FontFace(name, 'local("name")').load()`
 *
 * A `FontFace` whose only source is `local("name")` loads (fulfils) exactly when the system
 * has a font of that name, and rejects otherwise. All families are loaded together under
 * `Promise.allSettled`; fulfilled = installed. The faces are never added to
 * `document.fonts`, so nothing the page renders changes. `local()` is not a fetch, so the
 * CSP's `font-src 'self'` does not apply to it (measured: same results with that header).
 * This is the second of CreepJS's two font paths (catalogue §8).
 *
 * Measured 2026-10-05 against `fc-list` on the harness machine: Chromium 153, Firefox 155 and
 * WebKit 26.6 all reported exactly the installed families (DejaVu Sans, Liberation Sans,
 * Noto Color Emoji) and none of the absent ones, in 2-29 ms for 12 families.
 *
 * Honesty gate, kept from the first method: a face for `nc-no-such-font-7f3a`, which cannot
 * exist, must REJECT. If it fulfils, the engine (or an extension) answers yes to everything,
 * the bits say nothing, and the probe is `unavailable('check-dishonest')`.
 *
 * ## Why not `document.fonts.check()`, the method CONTRACT-2 V3 first specified
 *
 * The CSS Font Loading specification makes `check()` return TRUE when no face in the
 * document's `FontFaceSet` matches the family, and system fonts are never in that set. So it
 * cannot tell installed from absent: measured on the same day, `check()` returned true for
 * the impossible sentinel and for every family tried, installed or not, in Chromium 153,
 * Firefox 155 and WebKit 26.6. The probe was `unavailable('check-dishonest')` everywhere.
 *
 * No `FontFace` → `unavailable('no-font-loading')`. All loads are bounded by
 * `FONT_FACES_TIMEOUT_MS`.
 */
export function fontFaces(): Promise<ProbeResult<FontFacesValue>> {
    const FontFaceCtor = typeof FontFace === 'function' ? FontFace : undefined;
    if (!FontFaceCtor) {
        return Promise.resolve(unavailable<FontFacesValue>('no-font-loading'));
    }

    const measure = async (): Promise<ProbeResult<FontFacesValue>> => {
        if (await hasLocalFont(FontFaceCtor, FONT_FACE_SENTINEL)) {
            return unavailable('check-dishonest');
        }

        return probeAsync('fontFaces', async (): Promise<FontFacesValue> => {
            const families: readonly string[] = [
                ...FONT_FACE_FAMILIES.windows, ...FONT_FACE_FAMILIES.mac, ...FONT_FACE_FAMILIES.linux,
                ...FONT_FACE_FAMILIES.android, ...FONT_FACE_FAMILIES.chromeos,
            ];
            const settled = await Promise.allSettled(families.map((family) => hasLocalFont(FontFaceCtor, family)));
            const present = new Map<string, boolean>(families.map((family, index) => {
                const outcome = settled[index];
                return [family, outcome?.status === 'fulfilled' && outcome.value] as const;
            }));
            const countOf = (group: readonly string[]): number => group.filter((family) => present.get(family)).length;

            return {
                count: countOf(families),
                windows: countOf(FONT_FACE_FAMILIES.windows),
                mac: countOf(FONT_FACE_FAMILIES.mac),
                linux: countOf(FONT_FACE_FAMILIES.linux),
                android: countOf(FONT_FACE_FAMILIES.android),
            };
        });
    };

    return withTimeout(
        measure().catch((error: unknown) => failed<FontFacesValue>(error)),
        FONT_FACES_TIMEOUT_MS,
    );
}

/** The physical keys whose produced characters identify a keyboard layout (CONTRACT-2 V6). */
export const KEYBOARD_CODES = [
    'KeyQ', 'KeyW', 'KeyE', 'KeyA', 'KeyZ', 'KeyY', 'KeyM', 'Semicolon', 'Quote', 'Backquote',
    'BracketLeft', 'Minus', 'Equal', 'Slash', 'Backslash', 'Digit2', 'Digit3',
] as const;

/** How long `keyboardLayout` waits for `getLayoutMap()`. */
export const KEYBOARD_LAYOUT_TIMEOUT_MS = 1000;

/**
 * The keyboard layout, from `navigator.keyboard.getLayoutMap()` (Keyboard Map API; Chromium
 * desktop only). TIER.HARDWARE.
 *
 * The characters 17 physical keys produce distinguish QWERTY from AZERTY from QWERTZ, the
 * US from the UK and international variants, and the non-Latin layouts. A layout is a
 * property of the operating system's configuration, shared by every browser on the device,
 * and nothing in the User-Agent claims it. Only a hash and the map size are sent:
 * `fnv1a32` of the 17 values in `KEYBOARD_CODES` order, joined by `,` (a missing key is the
 * empty string).
 *
 * `unavailable('no-keyboard-api')` in Firefox and Safari, which do not implement the API.
 * A rejection (for example in a cross-origin iframe, where the specification requires one)
 * is an `error`, and the call is bounded by `KEYBOARD_LAYOUT_TIMEOUT_MS`.
 *
 * Measured 2026-10-05: headless Chromium 153 resolves an EMPTY map (size 0), so the harness
 * value is the hash of 17 empty strings. A headed desktop browser is UNVERIFIED here.
 */
export function keyboardLayout(): Promise<ProbeResult<{ hash: string; size: number }>> {
    const keyboard = typeof navigator === 'undefined'
        ? undefined
        : (navigator as Navigator & { keyboard?: { getLayoutMap?: () => Promise<ReadonlyMap<string, string>> } }).keyboard;
    const getLayoutMap = keyboard?.getLayoutMap;
    if (!keyboard || typeof getLayoutMap !== 'function') {
        return Promise.resolve(unavailable('no-keyboard-api'));
    }

    return withTimeout(
        probeAsync('keyboardLayout', async () => {
            const map = await getLayoutMap.call(keyboard);
            const values = KEYBOARD_CODES.map((code) => {
                const value: unknown = map.get(code);
                return typeof value === 'string' ? value : '';
            });

            return { hash: fnv1a32(values.join(',')), size: typeof map.size === 'number' ? map.size : 0 };
        }),
        KEYBOARD_LAYOUT_TIMEOUT_MS,
    );
}

/** The worker counts `parallelism` measures with, in order. */
export const PARALLELISM_ROUNDS = [1, 2, 4, 8] as const;

/** How long each worker spins in a round. */
export const PARALLELISM_SPIN_MS = 40;

/**
 * The warm-up spin each worker runs before the measured one, which doubles as its ready
 * signal, so the measured loop is already JIT-compiled in every worker.
 */
export const PARALLELISM_WARMUP_MS = 20;

/**
 * How many times the 1-2-4-8 sequence is run on the same warmed workers; the best reading
 * over all of them is kept. A busy machine LOWERS a reading and never raises it, so a second
 * pass about 200 ms later is what keeps one transient load from flipping the bucket: with one
 * pass, WebKit 26.6 read a 4-core machine as '1-2' on 1 of 6 harness loads (2026-10-05).
 */
export const PARALLELISM_PASSES = 2;

/** How long the whole measurement (start-up, warm-up and every round of every pass) may take. */
export const PARALLELISM_TIMEOUT_MS = 4000;

/** `tier2.parallelism` on the wire. Only `bucket` is a claim; the rest is stripped by name. */
export interface ParallelismValue {
    readonly bucket: '1-2' | '3-4' | '5-8' | '9+';
    readonly elapsedMs: {
        readonly t1: number;
        readonly t2: number;
        readonly t4: number;
        readonly t8: number;
        /** The measured capacity behind `bucket`: volatile, so it lives under the stripped key. */
        readonly capacity: number;
    };
}

/** Rejection of the measurement, carrying the `unavailable` reason. Never on the wire. */
class RoundFailure extends Error {
    constructor(readonly reason: string) {
        super(reason);
    }
}

/** One round's result: its wall time and each spinning worker's work count. */
export interface SpinRound {
    readonly wallMs: number;
    readonly iterations: readonly number[];
}

/**
 * The measurement session: start the largest round's workers ONCE, warm every one up
 * (`PARALLELISM_WARMUP_MS`, which also proves it answers), then run the rounds in order on
 * the first k of those same warmed workers, `PARALLELISM_PASSES` times over. Every worker is terminated on every outcome,
 * including `releaseShared()`. Rejects with a `RoundFailure`.
 *
 * Reusing warmed workers instead of starting fresh ones per round is what made the claim
 * steadier: with fresh workers each round measured a differently-warm JIT, and the
 * one-worker round in particular came in slow on a cold page (Firefox 155 read a 4-core
 * machine as up to 7.3 cores, '5-8' in 6 of 30 runs, 2026-10-05).
 */
function parallelSession(): Promise<SpinRound[]> {
    return new Promise((resolve, reject) => {
        const size = PARALLELISM_ROUNDS[PARALLELISM_ROUNDS.length - 1] as number;
        const workers: Worker[] = [];
        const warmed = new Set<number>();
        const rounds: SpinRound[] = [];
        let round = -1;
        let roundStarted = 0;
        let counts: number[] = [];
        let settled = false;
        let timer: ReturnType<typeof setTimeout> | undefined;
        let unregister: (() => void) | undefined;

        const finish = (outcome: SpinRound[] | RoundFailure): void => {
            if (settled) return;
            settled = true;
            if (timer !== undefined) clearTimeout(timer);
            unregister?.();
            for (const worker of workers) {
                try {
                    worker.terminate();
                } catch {
                    /* already gone */
                }
            }
            if (outcome instanceof RoundFailure) reject(outcome);
            else resolve(outcome);
        };

        const total = PARALLELISM_ROUNDS.length * PARALLELISM_PASSES;
        const startRound = (index: number): void => {
            round = index;
            const count = PARALLELISM_ROUNDS[index % PARALLELISM_ROUNDS.length] as number;
            counts = new Array<number>(count).fill(-1);
            roundStarted = nowMs();
            for (let w = 0; w < count; w++) workers[w]?.postMessage({ ask: 'spin', ms: PARALLELISM_SPIN_MS });
        };

        const onReply = (index: number, data: unknown): void => {
            const done = spinIterations(data);
            if (done === null) {
                finish(new RoundFailure('malformed'));
                return;
            }
            if (round < 0) {
                warmed.add(index);
                if (warmed.size === size) startRound(0);
                return;
            }
            if (index >= counts.length || (counts[index] as number) >= 0) {
                finish(new RoundFailure('malformed'));
                return;
            }
            counts[index] = done;
            if (counts.every((value) => value >= 0)) {
                rounds.push({ wallMs: nowMs() - roundStarted, iterations: counts });
                if (round + 1 < total) startRound(round + 1);
                else finish(rounds);
            }
        };

        try {
            unregister = onRelease(() => finish(new RoundFailure('released')));
            timer = setTimeout(() => finish(new RoundFailure('timeout')), PARALLELISM_TIMEOUT_MS);

            for (let index = 0; index < size && !settled; index++) {
                let worker: Worker;
                try {
                    worker = createScopeWorker();
                } catch {
                    finish(new RoundFailure('blocked'));
                    return;
                }
                workers.push(worker);
                worker.addEventListener('message', (event: MessageEvent) => onReply(index, event.data));
                worker.addEventListener('messageerror', () => finish(new RoundFailure('malformed')));
                worker.addEventListener('error', (event: Event) => {
                    event.preventDefault();
                    finish(new RoundFailure('blocked'));
                });
                worker.postMessage({ ask: 'spin', ms: PARALLELISM_WARMUP_MS });
            }
        } catch {
            finish(new RoundFailure('blocked'));
        }
    });
}

/**
 * The effective parallel capacity of a session, in single-core equivalents: for each round,
 * the total work of its k workers divided by the work ONE worker does on a core of its own,
 * and the largest such ratio over the rounds.
 *
 * The single-core reference is the most work any one worker did in any round, not the
 * one-worker round alone: a worker cannot do more than a whole core's work, so the maximum is
 * the steadiest estimate of a core, and no round's ratio can then exceed its k. Null when no
 * worker did any work.
 */
export function parallelCapacity(rounds: readonly SpinRound[]): number | null {
    const core = Math.max(0, ...rounds.flatMap((round) => round.iterations));
    if (core <= 0) return null;

    return Math.max(...rounds.map((round) => round.iterations.reduce((sum, value) => sum + value, 0) / core));
}

/**
 * The bucket of an effective parallel capacity (single-core equivalents, `parallelCapacity`).
 *
 * Measured with the final method on a 4-core VM, 30 runs per engine (2026-10-05): Chromium 153
 * 3.69-4.68, Firefox 155 2.62-4.33, WebKit 26.6 2.80-3.71 — every run in '3-4' with these
 * boundaries. A reading cannot exceed its round's k and, with the fastest-worker reference,
 * barely exceeds the real core count, so the boundaries sit just above 2 and 4 (2.5, 5) and
 * at 9.5. With k at most 8 the reading cannot exceed 8: '9+' is unreachable and a 16-core
 * machine reads '5-8'.
 */
export function parallelismBucket(capacity: number): ParallelismValue['bucket'] {
    if (capacity <= 2.5) return '1-2';
    if (capacity <= 5) return '3-4';
    if (capacity <= 9.5) return '5-8';
    return '9+';
}

/**
 * Measured parallel capacity, as a bucket. TIER.HARDWARE, async; DEFAULT-DISABLED by the
 * server's method policy (eight workers and about 0.3-0.5 s of wall time, spent off the main
 * thread).
 *
 * `navigator.hardwareConcurrency` is a number any script can redefine, and anti-detect
 * browsers do. Cores cannot be redefined: k workers busy-loop together for
 * `PARALLELISM_SPIN_MS` and count the work they got done. On c cores, k ≤ c workers each get
 * a core of their own and k > c share them, so a round's total work, in units of one core's
 * work, is about min(k, c). The capacity is the largest such reading over k ∈ {1, 2, 4, 8}
 * (`parallelCapacity`), bucketed by `parallelismBucket`; the server compares the bucket with
 * the claimed core count (`cores_vs_measured_parallelism`).
 *
 * Why work counts and not the wall-time ratio the contract sketches (`t_1 / t_k × k`): the V7
 * message spins for a fixed DURATION, so every round's wall time is about the same 40 ms
 * whatever the core count; the work done in that time is what scales. The round wall times
 * and the raw capacity are still reported, under `elapsedMs`, so they are stripped before
 * hashing and only the bucket is a claim.
 *
 * ## How the claim was made stable across loads (harness check (c))
 *
 * The first version started fresh workers for every round and divided by the one-worker
 * round. On a 4-core VM that read 2.5-4.7 in Chromium 153, 3.0-7.3 in Firefox 155 and
 * 1.7-3.3 in WebKit 26.6 (30 runs each, 2026-10-05), so the bucket flipped between loads in
 * all three engines. Three changes, each measured:
 * 1. The eight workers are started once and warmed up (`PARALLELISM_WARMUP_MS`), and every
 *    round reuses the first k of them, so no round measures a cold JIT or a worker still
 *    starting up. This alone removed WebKit's collapse (its 8-worker round had read 0.96-2.3).
 * 2. One core's work is the most any single worker did in any round, not the one-worker
 *    round alone, so a slow first round no longer inflates every ratio.
 * 3. The worker's loop does arithmetic between clock reads (`scope.worker.ts`), so it counts
 *    CPU work rather than clock calls.
 * Result: 3.69-4.68 / 2.62-4.33 / 2.80-3.71, '3-4' in 89 of 90 runs before the lowest
 * boundary was set at 2.5, and in 90 of 90 after. Under a full collection WebKit still read
 * '1-2' once in 6 harness loads, so 4. the whole sequence runs twice (`PARALLELISM_PASSES`)
 * and the best reading over both passes is kept; the reported times are the first pass's.
 *
 * It measures the cores this page can USE, which a CPU quota or a heavily loaded machine
 * lowers; the server should treat a bucket BELOW the claimed core count as weaker evidence
 * than one above it.
 *
 * Same worker as `workerScope` (`scope.worker.ts`, same origin, CSP-safe; a Blob worker is
 * not allowed). `unavailable`: `no-worker`, `blocked`, `timeout` (`PARALLELISM_TIMEOUT_MS`
 * for the whole session), `malformed`, `released` (every worker terminated in
 * `releaseShared()`), `unmeasurable` (no worker did any work).
 */
export async function parallelism(): Promise<ProbeResult<ParallelismValue>> {
    if (typeof Worker !== 'function') {
        return unavailable<ParallelismValue>('no-worker');
    }

    let rounds: SpinRound[];
    try {
        rounds = await parallelSession();
    } catch (error) {
        return error instanceof RoundFailure ? unavailable(error.reason) : failed(error);
    }

    const capacity = parallelCapacity(rounds);
    if (capacity === null) return unavailable('unmeasurable');
    const wall = rounds.map((round) => Math.round(round.wallMs * 10) / 10);

    return ok({
        bucket: parallelismBucket(capacity),
        elapsedMs: {
            t1: wall[0] as number,
            t2: wall[1] as number,
            t4: wall[2] as number,
            t8: wall[3] as number,
            capacity: Math.round(capacity * 100) / 100,
        },
    });
}

// =====================================================================
// Registry
// =====================================================================

/**
 * A probe split into steps, each one unit of synchronous main-thread work the scheduler
 * may run in a separate idle slice. `result()` is read after the last step.
 */
export interface ProbeSteps<T> {
    readonly steps: ReadonlyArray<() => void>;
    readonly result: () => T;
}

/** Run every step at once and return the result: the un-sliced form of a stepped probe. */
export function runSteps<T>(stepped: ProbeSteps<T>): T {
    for (const step of stepped.steps) step();

    return stepped.result();
}

export interface ValueProbe {
    readonly name: string;
    readonly tier: Tier;
    readonly run: () => ProbeResult<unknown> | Promise<ProbeResult<unknown>>;
    /**
     * The same measurement as `run`, in steps the scheduler spreads over idle slices. The
     * value MUST equal `run()`'s; `run` stays the one the synchronous callers use.
     */
    readonly stepped?: () => ProbeSteps<unknown>;
    /**
     * Scheduling: a known first-use cost (a context, a renderer's first font matching, a
     * shader compile) — always started at the beginning of a fresh idle period, never
     * appended to a slice another probe has already used part of.
     */
    readonly heavy?: boolean;
    /** Scheduling: after every other deferred probe (the audio probes, decision G-D5i). */
    readonly late?: boolean;
    /** Scheduling: wait for `document.fonts.ready` (bounded) before the first step. */
    readonly needsFonts?: boolean;
}

/**
 * The probe set. Tier 1 is synchronous and cheap; tiers 2 and HARDWARE run in idle
 * slices (`runDeferred`). The per-probe cost is machine-specific and is measured,
 * not asserted, by tests/Browser/transport-checks.mjs on all three engines.
 */
export const VALUE_PROBES: readonly ValueProbe[] = [
    // Tier 1 — the synchronous part.
    { name: 'dateParsing', tier: TIER.ONE, run: dateParsing },
    { name: 'cssMedia', tier: TIER.ONE, run: cssMedia },
    { name: 'codecs', tier: TIER.ONE, run: codecs },
    { name: 'esFeatures', tier: TIER.ONE, run: esFeatures },
    { name: 'environment', tier: TIER.ONE, run: environment },
    { name: 'uaClientHints', tier: TIER.ONE, run: uaClientHints },
    { name: 'objectShape', tier: TIER.ONE, run: objectShape },
    { name: 'removedApiBoundary', tier: TIER.ONE, run: removedApiBoundary },
    { name: 'architecture', tier: TIER.ONE, run: architecture },
    { name: 'engineIdentity', tier: TIER.ONE, run: engineIdentity },       // <= 0.1 ms

    // Tier 2 — deferred to idle time. Engine-level signals. Cold costs are round-2 harness
    // figures (Chromium / Firefox / WebKit where they differ); `heavy` marks the ones the
    // scheduler always starts in a fresh idle period.
    // `workerScope` first, so its worker starts in the first idle slice and its off-thread
    // start-up overlaps the main-thread probes that follow.
    { name: 'workerScope', tier: TIER.TWO, run: workerScope },                     // off-thread round trip
    { name: 'textMetrics', tier: TIER.TWO, run: textMetrics, heavy: true },        // 12 ms cold (first canvas text)
    { name: 'errorText', tier: TIER.TWO, run: errorText, heavy: true },            // 8-71 ms cold (first ICU errors)
    { name: 'permissions', tier: TIER.TWO, run: permissions },                     // 12 ms cold, async
    { name: 'canvasGeometry', tier: TIER.TWO, run: canvasGeometry, heavy: true },  // 17-193 ms cold (shared WebGL context)
    { name: 'fontFallback', tier: TIER.TWO, run: fontFallback, heavy: true },      // 17 ms cold
    { name: 'intl', tier: TIER.TWO, run: intl, heavy: true },                      // 10-105 ms cold (ICU)
    { name: 'timezoneLmt', tier: TIER.TWO, run: timezoneLmt },
    // Heavy since round-3 CL3-5: it creates an OfflineAudioContext, and in the slice it shared
    // with intl + timezoneLmt that slice measured 50-56 ms at 4x CPU throttling.
    { name: 'audioReadback', tier: TIER.TWO, run: audioReadback, heavy: true },    // 256-frame offline render, async
    { name: 'heapMemory', tier: TIER.TWO, run: heapMemory },                       // gated on COI
    // Moved from tier 1: 10-11 ms COLD (first ICU table load), <1 ms warm, and an engine
    // build signal nothing needs synchronously. It therefore no longer feeds the browser
    // key (tier 1 only) — a one-time re-key, inside the v3 protocol change.
    { name: 'buildFingerprint', tier: TIER.TWO, run: buildFingerprint, heavy: true },
    // LAST slices (decision G-D5i, round-2 PERF-6): creating the realtime `AudioContext` costs
    // 34-210 ms cold and nothing else waits for it. `late` moves it after every other
    // deferred probe of BOTH tiers; the tier (and so the wire block) is unchanged.
    { name: 'audioRealtime', tier: TIER.TWO, run: audioRealtime, heavy: true, late: true },
    { name: 'audioOffline', tier: TIER.TWO, run: audioOffline, late: true },       // 2-4 ms, async render

    // Tier HARDWARE — the cross-browser device/OS signals, after tier 2. Sent under `tier2`.
    // Stepped over FONT_METRICS_STEPS slices; `run` is the un-sliced form for the diagnostics.
    { name: 'fontMetrics', tier: TIER.HARDWARE, run: fontMetrics, stepped: fontMetricsSteps, heavy: true, needsFonts: true }, // 3-7 ms warm, 69-294 ms cold
    // Heavy since round-3 CL3-5: the first measure loads the OS colour-emoji font; appended to
    // the last fontMetrics step that slice measured 58 ms at 4x CPU throttling.
    { name: 'emojiMetrics', tier: TIER.HARDWARE, run: emojiMetrics, heavy: true, needsFonts: true },
    // Stepped over SCRIPTS_STEPS slices since round-3 CL3-5 (80-102 ms as one unit at 4x CPU).
    { name: 'scripts', tier: TIER.HARDWARE, run: scripts, stepped: scriptsSteps, heavy: true, needsFonts: true },  // 7-104 ms cold (font fallback)
    { name: 'gpu', tier: TIER.HARDWARE, run: gpu, heavy: true },                   // first WebGL context where canvasGeometry did not create it
    { name: 'gpuMath', tier: TIER.HARDWARE, run: gpuMath, heavy: true },           // shader compile cold, ≤2 ms warm
    { name: 'decoders', tier: TIER.HARDWARE, run: decoders },                      // async
    { name: 'voices', tier: TIER.HARDWARE, run: voices },                          // up to VOICES_WAIT_MS of WAIT, not work
    { name: 'fontFaces', tier: TIER.HARDWARE, run: fontFaces },                    // async local() loads
    { name: 'keyboardLayout', tier: TIER.HARDWARE, run: keyboardLayout },          // Chromium desktop only, async
    // In its own idle slice: its workers spin off the main thread and should not share the
    // CPU with another probe's work. Default-disabled by the server's policy.
    { name: 'parallelism', tier: TIER.HARDWARE, run: parallelism, heavy: true },   // 4 rounds of workers, off-thread
    // The second audio probe, after everything else (G-D5i): reads the same shared context.
    { name: 'audioHardware', tier: TIER.HARDWARE, run: audioHardware, late: true },
];

/** Probes of one tier, in registry order. */
export function probesOf(tier: Tier): readonly ValueProbe[] {
    return VALUE_PROBES.filter((entry) => entry.tier === tier);
}

/**
 * Probes of one tier minus the ones the method policy disables.
 *
 * Core probes run even when named (defence in depth: `effectiveDisabled()` has normally
 * removed them already), and a name that matches no probe changes nothing.
 */
export function enabledProbesOf(tier: Tier, disabled: readonly string[] = []): readonly ValueProbe[] {
    return probesOf(tier).filter((entry) => CORE_PROBES.includes(entry.name) || !disabled.includes(entry.name));
}

/**
 * Run the probes for a tier, all started at once.
 *
 * Most of the cost is synchronous rasterisation that the event loop cannot overlap,
 * while the async probes (UA-CH, permissions, audio) can, so the wall time is close to
 * the slowest probe rather than the sum. Used for tier 1 and for the diagnostics.
 */
export async function runTier(
    tier: Tier,
    disabled: readonly string[] = [],
): Promise<Record<string, ProbeResult<unknown> | Promise<ProbeResult<unknown>>>> {
    const entries = await Promise.all(
        enabledProbesOf(tier, disabled).map(async (entry) => [entry.name, entry.run()] as const),
    );

    return Object.fromEntries(entries);
}

// =====================================================================
// The deferred scheduler
// =====================================================================

/**
 * What is left of the current idle period. `IdleDeadline` where the engine gave one; a
 * fixed budget counted from the slice's start where it did not (WebKit has no
 * `requestIdleCallback`: BCD lists Safari as behind a flag, and the harness measured
 * `typeof requestIdleCallback === 'undefined'` in WebKit 26.6).
 */
export interface IdleBudget {
    timeRemaining(): number;
}

/** The budget a slice gets where no `IdleDeadline` exists: one frame. */
export const FALLBACK_SLICE_MS = 16;

/** `requestIdleCallback`'s timeout: a slice runs after at most this long on a page that never goes idle. */
export const IDLE_TIMEOUT_MS = 1000;

/**
 * The least an idle period must still have for the NEXT unit to start in it rather than in
 * a fresh one. Below this the slice is handed back, so a cheap probe never spills past the
 * deadline by more than its own cost.
 */
export const MIN_SLICE_REMAINING_MS = 5;

/** How long the scheduler waits for `document.fonts.ready` before the first font-dependent unit. */
export const FONTS_READY_WAIT_MS = 300;

const budgetFrom = (startedAt: number, ms: number): IdleBudget => ({
    timeRemaining: () => Math.max(0, ms - (nowMs() - startedAt)),
});

/**
 * Resolve at the start of the next idle period with what is left of it.
 *
 * `requestIdleCallback` where it exists (`IDLE_TIMEOUT_MS` makes the callback run even when
 * the page never goes idle, with `timeRemaining()` then 0); otherwise `scheduler.yield()`
 * where it exists, or a 16 ms timer, each followed by a `FALLBACK_SLICE_MS` budget. The
 * callers before 2026-10-08 ignored the value; they still can.
 */
export function nextIdle(): Promise<IdleBudget> {
    return new Promise((resolve) => {
        if (typeof requestIdleCallback === 'function') {
            requestIdleCallback((deadline) => resolve(deadline), { timeout: IDLE_TIMEOUT_MS });
            return;
        }
        const fallback = (): void => resolve(budgetFrom(nowMs(), FALLBACK_SLICE_MS));
        const sched = (globalThis as { scheduler?: { yield?: () => Promise<void> } }).scheduler;
        if (sched && typeof sched.yield === 'function') {
            // `scheduler.yield()`, where the engine implements it, continues after the event
            // loop has run other tasks; the budget then counts from the continuation.
            try {
                sched.yield().then(fallback, () => setTimeout(fallback, FALLBACK_SLICE_MS));
                return;
            } catch {
                /* an implementation that throws is treated as absent */
            }
        }
        setTimeout(fallback, FALLBACK_SLICE_MS);
    });
}

/**
 * Wait for the document's fonts to be ready, at most `ms`. Never throws, resolves at once
 * where `document.fonts` is absent (round-2 STD-23: a cold Firefox renderer measured the
 * Myanmar sample of `scripts` as `.notdef` before its font fallback had loaded).
 */
export function fontsReady(ms = FONTS_READY_WAIT_MS): Promise<void> {
    return new Promise((resolve) => {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const done = (): void => {
            if (timer !== undefined) clearTimeout(timer);
            resolve();
        };
        try {
            const ready = (document as Document & { fonts?: { ready?: Promise<unknown> } }).fonts?.ready;
            if (!ready || typeof ready.then !== 'function') {
                resolve();
                return;
            }
            timer = setTimeout(done, ms);
            ready.then(done, done);
        } catch {
            done();
        }
    });
}

/** One unit of scheduled work: a whole probe, or one step of a stepped probe. */
export interface UnitTrace {
    readonly name: string;
    /** `step/steps` for a stepped probe's unit, else null. */
    readonly step: string | null;
    /** Index of the idle slice the unit ran in; units sharing a slice share the number. */
    readonly slice: number;
    /** `performance.now()` when the unit started and when it settled. */
    readonly startMs: number;
    readonly endMs: number;
    /** `timeRemaining()` of the slice when the unit started. */
    readonly remainingMs: number;
}

export interface DeferredOptions {
    readonly disabled?: readonly string[];
    /**
     * Polled before every unit, again after the wait for its idle slice, between the steps of
     * a stepped probe and after the fonts wait: true stops the schedule. What settled so far is
     * in `out`; a unit already running completes (it cannot be interrupted) and is also written
     * there. A stepped probe cut short is ABSENT from `out` (half its families measured would
     * be a different value, not a partial one).
     */
    readonly aborted?: () => boolean;
    /** Per-unit timings, for the diagnostics; nothing here is hashed or sent. */
    readonly trace?: (unit: UnitTrace) => void;
    /** The record the results are written to AS THEY SETTLE, so an abort can read a partial set. */
    readonly out?: Record<string, ProbeResult<unknown>>;
    /** The number the first slice gets in the trace (a caller that used slices before passes how many). */
    readonly firstSlice?: number;
}

/** `runDeferred`'s internal marker: the unit did not run because the schedule was aborted. */
const SKIPPED = Symbol('skipped');

/**
 * The deferred probes of the given tiers, scheduled into idle time (decision G-D5i):
 *
 * - ONE unit at a time — a probe, or one step of a stepped probe (`fontMetrics`, six
 *   family chunks on one canvas; `scripts`, four sample chunks) — never several probes
 *   started together in a slice;
 * - deadline-aware: a unit starts in the current idle period only if
 *   `timeRemaining() >= MIN_SLICE_REMAINING_MS`, else in the next one (`nextIdle`); a
 *   `heavy` unit always takes a fresh period;
 * - `late` probes (the audio probes) after every other probe of every tier given;
 * - `document.fonts.ready` awaited (bounded) once, before the first `needsFonts` unit;
 * - an async probe's wait (a worker reply, an offline render) is not slice time: when it
 *   settles the deadline has usually passed and the next unit takes a fresh period;
 * - never throws: a step that throws makes its probe `error`, like `probe()` would;
 * - abortable between units: `aborted()` is checked before a unit, after the idle wait that
 *   precedes it and after the fonts wait, so nothing starts once the caller has given up
 *   (round-3 CL3-3: after the identify cap, `fontMetrics` used to take two more slices whose
 *   result was already discarded).
 *
 * Slicing chooses WHEN a probe starts. A cold first-use cost is still one task; the harness
 * measures every slice with the Long Tasks API and ratchets the warm ones (≤ 50 ms).
 */
export async function runDeferred(tiers: readonly Tier[], options: DeferredOptions = {}): Promise<Record<string, ProbeResult<unknown>>> {
    const out = options.out ?? {};
    const aborted = options.aborted ?? ((): boolean => false);
    const disabled = options.disabled ?? [];

    const entries = tiers.flatMap((tier) => enabledProbesOf(tier, disabled));
    const ordered = [...entries.filter((entry) => !entry.late), ...entries.filter((entry) => entry.late)];

    let budget: IdleBudget | null = null;
    let slice = (options.firstSlice ?? 0) - 1;
    let fontsAwaited = false;

    const freshSlice = async (): Promise<void> => {
        budget = await nextIdle();
        slice++;
    };

    /**
     * Run one unit in a slice that still has room (or a fresh one), recording its trace.
     * Resolves to `SKIPPED` without running `work` when the schedule was aborted, including
     * while it waited for the slice.
     */
    const unit = async (name: string, step: string | null, heavy: boolean, work: () => ProbeResult<unknown> | Promise<ProbeResult<unknown>> | void): Promise<ProbeResult<unknown> | void | typeof SKIPPED> => {
        if (aborted()) return SKIPPED;
        if (budget === null || heavy || budget.timeRemaining() < MIN_SLICE_REMAINING_MS) {
            await freshSlice();
            if (aborted()) return SKIPPED;
        }
        const remainingMs = (budget as IdleBudget).timeRemaining();
        const startMs = nowMs();
        try {
            return await work();
        } finally {
            options.trace?.({ name, step, slice, startMs, endMs: nowMs(), remainingMs });
        }
    };

    for (const entry of ordered) {
        if (aborted()) break;
        if (entry.needsFonts && !fontsAwaited) {
            fontsAwaited = true;
            await fontsReady();
            // The wait left the idle period; the unit takes a fresh one.
            budget = null;
            if (aborted()) break;
        }

        if (entry.stepped) {
            let stepped: ProbeSteps<unknown>;
            try {
                stepped = entry.stepped();
            } catch (error) {
                out[entry.name] = failed(error);
                continue;
            }
            let broken = false;
            let cut = false;
            for (const [index, step] of stepped.steps.entries()) {
                try {
                    if ((await unit(entry.name, `${index + 1}/${stepped.steps.length}`, entry.heavy === true, step)) === SKIPPED) {
                        cut = true;
                        break;
                    }
                } catch (error) {
                    out[entry.name] = failed(error);
                    broken = true;
                    break;
                }
            }
            if (cut) break;
            if (!broken) {
                try {
                    out[entry.name] = ok(stepped.result());
                } catch (error) {
                    out[entry.name] = failed(error);
                }
            }
            continue;
        }

        try {
            const result = await unit(entry.name, null, entry.heavy === true, entry.run);
            if (result === SKIPPED) break;
            out[entry.name] = result as ProbeResult<unknown>;
        } catch (error) {
            // `run` never throws by contract (`probe`/`probeAsync`); if one does, the
            // tagged form is the same as everywhere else.
            out[entry.name] = failed(error);
        }
    }

    return out;
}

/** One tier through the deferred scheduler. The form `collectTier2Block` used before `runDeferred`. */
export function runTierChunked(tier: Tier, disabled: readonly string[] = []): Promise<Record<string, ProbeResult<unknown>>> {
    return runDeferred([tier], { disabled });
}

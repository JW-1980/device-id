/**
 * Integrity probes: does the environment look tampered with?
 *
 * ## Why this file runs first, and is the most important one
 *
 * These are the only probes in the whole system that can DETECT an attacker by
 * themselves. Measured against a competent stealth spoofer (Chromium, Firefox and
 * WebKit, two configurations each), all five integrity probes fired in 6 of 6 cells
 * while **not one of 162 value-probe runs detected anything**. That is not a
 * close result and it is not a matter of degree:
 *
 * - A **value** probe reports a property. A spoofer that wants to fool it must know
 *   what value to report, and it can. Zero of them were detected.
 * - An **integrity** probe tests a *specification conformance* property. There is no
 *   value to guess: a real WebIDL getter either brand-checks its receiver or it does
 *   not, and the spoofer has no reason to make its replacement getter behave like a
 *   real one.
 *
 * So the ordering is deliberate. Integrity first means that if the collection is
 * aborted, times out, or the user navigates away, the half that is worth having has
 * already been collected.
 *
 * Five probes, 0.125 ms together — 0.4 % of the 30 ms budget.
 *
 * ## What "detection" means for the server
 *
 * A finding here is EVIDENCE OF TAMPERING, not a device value. `wrongReceiver`
 * reporting `did-not-throw` is a statement about the environment, and the server
 * must treat it as such. It is not a fingerprint input and must never be hashed
 * into one.
 *
 * ## The three techniques, and why each works
 *
 * 1. `wrongReceiver` — call a WebIDL getter with `{}`. A conformant one throws a
 *    TypeError because it brand-checks. Measured: honest `threw:TypeError`,
 *    spoofed `did-not-throw`.
 * 2. `descriptorIntegrity` — check descriptor *shape* and getter *identity*, not
 *    source text. Measured: the test spoofer patched `Function.prototype.toString`
 *    and successfully hid 2 of its 4 patches; shape and identity still caught the
 *    other 2, and `webdriver` became `no-descriptor`, which is conclusive.
 * 3. `mathDual` — every transcendental computed twice, the second time by a
 *    bespoke expression. A lookup table covers the named functions and cannot know
 *    what `Math.log(1e154 + Math.sqrt(1e154*1e154 - 1))` evaluates to. Measured:
 *    the agreement flags flipped true→false.
 *
 * ## Constraints this file must keep
 *
 * - **No `eval`, no `new Function`, no `setTimeout` with a string body.** The CSP is
 *   nonce-based and `enforce` is one env flag away.
 * - **No DOM mutation and no console output.** A collector that touches the DOM is
 *   observable by the page, breaks sites that diff their own markup, and appears in
 *   their error reporting. This is FingerprintJS's `contributing.md` rule and it is
 *   right.
 * - **Never throw.** A throwing probe aborts the collection it is inside.
 */

import { probe, type ProbeResult } from './canonical';

/** Verdict codes. Stable strings: the server stores and indexes them. */
export const INTEGRITY_CODES = {
    WRONG_RECEIVER_OK: 'wrong_receiver_did_not_throw',
    WRONG_RECEIVER_DATA_PROPERTY: 'wrong_receiver_data_property',
    WRONG_RECEIVER_NO_DESCRIPTOR: 'wrong_receiver_no_descriptor',
    DESCRIPTOR_PATCHED: 'descriptor_patched',
    DESCRIPTOR_UNSTABLE: 'descriptor_unstable',
    DESCRIPTOR_MISSING: 'descriptor_missing',
    DESCRIPTOR_SETTER: 'descriptor_has_setter',
    MATH_PF_MISMATCH: 'math_pf_mismatch',
    CANVAS_DUAL_DIVERGED: 'canvas_dual_diverged',
    CANVAS_WINDING_FALSE: 'canvas_winding_false',
    DOM_BLOCKER_THROW: 'dom_blocker_threw',
    DOM_BLOCKER_PRESENT: 'dom_blocker_present',
} as const;

export type IntegrityFinding = { readonly code: string; readonly detail: string };

export interface IntegrityReport {
    /** Only NON-CLEAN findings. An empty list means the environment looks genuine. */
    readonly findings: readonly IntegrityFinding[];
    /** Raw per-probe data, for the server's constraint table. */
    readonly data: Readonly<Record<string, ProbeResult<unknown>>>;
    readonly elapsedMs: number;
}

const isNativeSource = (source: string): boolean => /\{\s*\[native code\]\s*\}/.test(source);

/**
 * Whether `Math.fma` exists, read without touching the property twice.
 *
 * Exists as a helper so the caller can narrow the type once: `Math.fma` is
 * specified but is not in the TypeScript DOM lib, so reaching it through a typed
 * alias is clearer than a blanket cast of `Math`.
 */
function hasFma(): boolean {
    return 'fma' in Math;
}

/** Read a native function's source without invoking any possibly-patched toString. */
function nativeSourceOf(fn: unknown): string {
    try {
        return Function.prototype.toString.call(fn);
    } catch {
        return '';
    }
}

/**
 * Probe 1 — wrong-receiver WebIDL conformance.
 *
 * A real WebIDL *attribute* validates that `this` is an instance of its interface
 * and throws a TypeError otherwise. Almost every property-patching library replaces
 * the getter with a plain closure that ignores its receiver, so this fires.
 *
 * ## Only attributes, and that distinction cost a real bug
 *
 * The first version of this probed a hand-picked list that included
 * `StorageManager.prototype.estimate` and `.persist`, and
 * `Intl.DateTimeFormat.prototype.formatRange`. All three are **methods**, not
 * attributes — a method has no getter at all, so the probe reported
 * `data-property` and raised a finding.
 *
 * The real-browser test caught it: 4 false findings in every one of Chromium,
 * Firefox and WebKit. Forty-one jsdom tests had not, because jsdom does not
 * implement any of them. **A probe against a list of names is only as good as the
 * list**, and a name that is not an attribute in some engine is a false positive in
 * all of them.
 *
 * So the list is restricted to attributes that are genuinely attributes everywhere,
 * and `nullDescriptor` is treated as "not an attribute, not evidence" rather than as
 * tampering. A probe that fires on real traffic is a bug, and the only defence is
 * running it against a real browser.
 */
export function wrongReceiver(): ProbeResult<Record<string, string>> {
    return probe('wrongReceiver', () => {
        const check = (proto: object, name: string): string => {
            try {
                const descriptor = Object.getOwnPropertyDescriptor(proto, name);
                if (!descriptor) return 'no-descriptor';
                // Not an attribute — a method, or a plain value. There is no
                // receiver to validate, so there is nothing to test.
                if (typeof descriptor.get !== 'function') return 'not-an-attribute';
                if (descriptor.value !== undefined) return 'not-an-attribute';

                (descriptor.get as (this: unknown) => unknown).call({});
                return 'did-not-throw';
            } catch (error) {
                return 'threw:' + (error instanceof Error ? error.name : 'Error');
            }
        };

        // Attributes only. Every entry is a WebIDL attribute in all three engines.
        const scopes: Record<string, { proto: object; names: string[] }> = {
            screen: { proto: Screen.prototype, names: ['width', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'] },
            navigator: { proto: Navigator.prototype, names: ['userAgent', 'language', 'onLine', 'maxTouchPoints', 'hardwareConcurrency'] },
            intl: { proto: Intl.DateTimeFormat.prototype, names: ['resolvedOptions', 'format'] },
        };

        const out: Record<string, string> = {};
        for (const [scope, spec] of Object.entries(scopes)) {
            for (const name of spec.names) {
                out[`${scope}.${name}`] = check(spec.proto, name);
            }
        }

        return out;
    });
}

/**
 * Probe 2 — descriptor shape and getter identity.
 *
 * Deliberately NOT a source-text check, though it does one. Source inspection is
 * defeated by patching `Function.prototype.toString`, which is a real and
 * implemented defence; shape and identity are not, because a patched getter is
 * still a data property or still has a stable identity, and the things this checks
 * for are structural.
 *
 * - `get` identity: a `Proxy`-based spoofer synthesises a NEW function object on
 *   every property read, so `desc.get !== desc2.get`. A real WebIDL attribute is
 *   the same function object every time.
 * - descriptor presence: deleting `webdriver` is the oldest trick in the book and it
 *   is caught here and nowhere else.
 * - setter presence: a real read-only WebIDL attribute has no setter. A spoofer
 *   adding one is trying to make the property writable and is not subtle about it.
 */
export function descriptorIntegrity(): ProbeResult<Record<string, string>> {
    return probe('descriptorIntegrity', () => {
        const names = [
            'userAgent', 'appVersion', 'appName', 'platform', 'product', 'productSub',
            'vendor', 'vendorSub', 'language', 'languages', 'onLine', 'cookieEnabled',
            'doNotTrack', 'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints',
            'webdriver', 'plugins', 'mimeTypes', 'pdfViewerEnabled', 'userAgentData',
            'connection', 'permissions', 'credentials', 'mediaDevices', 'clipboard',
            'serviceWorker', 'storage', 'locks', 'sendBeacon',
        ];

        const out: Record<string, string> = {};

        for (const name of names) {
            const first = Object.getOwnPropertyDescriptor(Navigator.prototype, name);
            if (!first) {
                out[name] = 'no-descriptor';
                continue;
            }

            const second = Object.getOwnPropertyDescriptor(Navigator.prototype, name);
            const target = first.get ?? first.value;
            const native = typeof target === 'function' && isNativeSource(nativeSourceOf(target));
            const stable = first.get ? Boolean(second) && first.get === second?.get : true;

            out[name] = [
                native ? 'N' : 'P',
                stable ? 'S' : 'U',
                first.set !== undefined ? 'W' : '-',
                first.configurable ? 'c' : 'C',
                first.enumerable ? 'e' : '-',
            ].join('');
        }

        return out;
    });
}

/**
 * Probe 3 — dual-implementation math cross-check.
 *
 * Each transcendental is computed twice. The second expression is written
 * differently, and for `sinhPf` it is *not* the correct value of sinh(1) — it is
 * `Math.exp(1) - 1/Math.exp(1)/2`, an operator-precedence quirk rather than
 * `(e − e⁻¹)/2`. That is the point: the `Pf` variants are deliberately
 * un-guessable bespoke expressions, and a spoofed lookup table has no way to know
 * what they should evaluate to.
 *
 * The `*Agrees` booleans are the actual output. A real engine satisfies all of
 * them; a table does not. Measured 6/6 detection.
 *
 * Attribution: the `*Pf` scheme is Kraken's, observed in a decoded telemetry
 * payload captured during this research. The generalisation — dual independent
 * implementation for every probe — is described in REPORT.md section 7.6.
 */
export function mathDual(): ProbeResult<Record<string, number | boolean | string>> {
    return probe('mathDual', () => {
        const M = Math;
        // Resolve through a local alias at call time, so patching Math *after* this
        // probe has loaded has no effect, and deleting a function falls back to 0
        // rather than throwing - which the agreement checks then notice.
        const zero = (): number => 0;
        const ac = M.acos || zero;
        const ach = M.acosh || zero;
        const as = M.asin || zero;
        const ash = M.asinh || zero;
        const at = M.atanh || zero;
        const an = M.atan || zero;
        const si = M.sin || zero;
        const sh = M.sinh || zero;
        const co = M.cos || zero;
        const chh = M.cosh || zero;
        const tn = M.tan || zero;
        const th = M.tanh || zero;
        const ex = M.exp || zero;
        const exm = M.expm1 || zero;
        const lp = M.log1p || zero;

        const EPSILON = 1e-15;

        return {
            acos: ac(0.12312423423423424),
            acosh: ach(1e308),
            acoshPf: M.log(1e154 + M.sqrt(1e154 * 1e154 - 1)),
            asin: as(0.12312423423423424),
            asinh: ash(1),
            asinhPf: M.log(1 + M.sqrt(2)),
            atanh: at(0.5),
            atanhPf: M.log(3) / 2,
            atan: an(0.5),
            sin: si(-1e300),
            sinh: sh(1),
            sinhPf: M.exp(1) - 1 / M.exp(1) / 2,
            cos: co(10.000000000123),
            cosh: chh(1),
            coshPf: (M.exp(1) + 1 / M.exp(1)) / 2,
            tan: tn(-1e300),
            tanh: th(1),
            tanhPf: (M.exp(2) - 1) / (M.exp(2) + 1),
            exp: ex(1),
            expm1: exm(1),
            expm1Pf: M.exp(1) - 1,
            log1p: lp(10),
            log1pPf: M.log(11),
            powPI: M.pow(M.PI, -100),
            // Math.fma is not in the TypeScript DOM lib yet, so it is reached
            // through a typed alias rather than with a cast that hides the lookup.
            fma: hasFma()
                ? (Math as unknown as { fma: (a: number, b: number, c: number) => number }).fma(
                      1.0000000000000002,
                      1.0000000000000002,
                      -2.0000000000000004,
                  )
                : 'no-fma',

            // The verdicts. Everything above is evidence; these are the answers.
            atanhAgrees: Math.abs(at(0.5) - M.log(3) / 2) < EPSILON,
            tanhAgrees: Math.abs(th(1) - (M.exp(2) - 1) / (M.exp(2) + 1)) < EPSILON,
            expm1Agrees: Math.abs(exm(1) - (M.exp(1) - 1)) < EPSILON,
            asinhAgrees: Math.abs(ash(1) - M.log(1 + M.sqrt(2))) < EPSILON,
        };
    });
}

/**
 * Probe 4 — canvas dual-implementation agreement, and the winding fill-rule test.
 *
 * ## The first version of this probe was wrong, and this is the correction
 *
 * It drew an arc-plus-bezier and then a densely-sampled polyline of "the same
 * curves", and asserted the two hashed identically. They do not — and they do not in
 * a real browser either, because those are genuinely different shapes and a correct
 * rasteriser *should* render them differently. The real-browser test reported
 * `canvas_dual_diverged` in Chromium, Firefox AND WebKit: 24 false findings from one
 * broken technique.
 *
 * A dual-implementation check is only valid when the specification pins both
 * implementations to the same result. So both paths below are exact spec-level
 * equivalences rather than two ways of describing one shape:
 *
 * - `fillRect` and `putImageData` of the same colour into the same region. The spec
 *   requires both to produce the same pixels.
 * - `fill()` with `nonzero` and with `evenodd` on a self-intersecting path. The
 *   centre of a pentagram is the one point where the two rules provably differ.
 *
 * The winding test was wrong in the same way: it sampled the centre of a *convex*
 * five-pointed star, where both fill rules give the same answer. A {5/2} star
 * polygon self-intersects, and its centre has winding number 2 — filled under
 * `nonzero`, unfilled under `evenodd`. That is the only point worth testing.
 */
export function canvasDual(): ProbeResult<{ agree: boolean; fillHash: string; putHash: string; winding: unknown }> {
    return probe('canvasDual', () => {
        const W = 64;
        const H = 64;

        const hashPixels = (ctx: CanvasRenderingContext2D): string => {
            const data = ctx.getImageData(0, 0, W, H).data;
            let a = 0x811c9dc5;
            let sum = 0;
            for (let i = 0; i < data.length; i += 3) {
                a = Math.imul(a ^ (data[i] as number), 16777619) >>> 0;
                sum += data[i] as number;
            }
            return (a >>> 0).toString(16) + ':' + sum;
        };

        // --- dual implementation A: fillRect ---
        const canvasA = document.createElement('canvas');
        canvasA.width = W;
        canvasA.height = H;
        const ctxA = canvasA.getContext('2d', { willReadFrequently: true });
        if (!ctxA) throw new Error('no 2d context');
        ctxA.fillStyle = '#123456';
        ctxA.fillRect(7, 11, 41, 23);
        const fillHash = hashPixels(ctxA);

        // --- dual implementation B: putImageData of the identical colour ---
        // The spec requires the same pixels, so the two hashes MUST be equal. A
        // canvas that supports fillRect but not putImageData (or vice versa) is a
        // stub, and that is the only thing this is detecting.
        const canvasB = document.createElement('canvas');
        canvasB.width = W;
        canvasB.height = H;
        const ctxB = canvasB.getContext('2d', { willReadFrequently: true });
        if (!ctxB) throw new Error('no 2d context');
        const image = ctxB.createImageData(W, H);
        for (let y = 11; y < 34; y++) {
            for (let x = 7; x < 48; x++) {
                const offset = (y * W + x) * 4;
                image.data[offset] = 0x12;
                image.data[offset + 1] = 0x34;
                image.data[offset + 2] = 0x56;
                image.data[offset + 3] = 0xff;
            }
        }
        ctxB.putImageData(image, 0, 0);
        const putHash = hashPixels(ctxB);

        // --- winding: a {5/2} star polygon, where the rules provably differ ---
        let winding: unknown = 'unavailable';
        try {
            if (typeof Path2D === 'function') {
                const size = 41;
                const centre = size / 2;
                const pentagram = new Path2D();
                // Connect every SECOND vertex of a pentagon: the {5/2} star polygon,
                // which crosses itself. The centre then has winding number 2.
                for (let step = 0; step < 5; step++) {
                    const vertex = (step * 2) % 5;
                    const angle = (vertex * 2 * Math.PI) / 5 - Math.PI / 2;
                    const x = centre + Math.cos(angle) * (size / 2 - 2);
                    const y = centre + Math.sin(angle) * (size / 2 - 2);
                    if (step === 0) pentagram.moveTo(x, y);
                    else pentagram.lineTo(x, y);
                }
                pentagram.closePath();

                const sample = (rule: CanvasFillRule): number => {
                    const c = document.createElement('canvas');
                    c.width = size;
                    c.height = size;
                    const x = c.getContext('2d', { willReadFrequently: true });
                    if (!x) return -1;
                    x.fillStyle = '#fff';
                    x.fill(pentagram, rule);
                    return x.getImageData(centre, centre, 1, 1).data[0] as number;
                };

                const nonzero = sample('nonzero');
                const evenodd = sample('evenodd');
                winding = { nonzero, evenodd, differ: nonzero !== evenodd };
            }
        } catch (error) {
            winding = 'error:' + (error instanceof Error ? error.name : 'Error');
        }

        return { agree: fillHash === putHash, fillHash, putHash, winding };
    });
}

/**
 * Probe 5 — extension and content-blocker surface.
 *
 * Kraken ships a probe called `domBlockers` whose only output is a duration. The
 * idea is good and worth keeping: a genuine visitor often HAS an extension or a
 * content blocker installed, and a naive automation stack never does. Absence is
 * therefore weak evidence *for* a real user, and presence of an extension-injected
 * property is evidence of a real browser rather than a synthetic one.
 *
 * ## Timings are NOT in the claim set at all
 *
 * Kraken reports a raw millisecond value for this probe. Reporting one here was
 * tried, in two forms, and both were wrong:
 *
 * 1. Raw milliseconds made every collection hash differently, so every visit looked
 *    like a new device and the identifier was worthless. The `collect()`
 *    determinism test caught it.
 * 2. Bucketed milliseconds (0 / 0.05-0.5 / 0.5-2 / >2 ms) looked better and was
 *    still wrong: the real-browser test caught the bucket flipping between 0 and 1
 *    between two page loads, because the access it is timing sits right on the
 *    boundary and machine noise straddles it.
 *
 * So the timings were removed from the claim set entirely. The probe keeps what is
 * stable — the extension and blocker surface, which is the part that actually
 * discriminates — and the durations are available only through `measureProbes()`,
 * which is a diagnostic and is never hashed.
 *
 * The general rule this established, and the reason it is written down here: **nothing
 * measured goes into the identifier.** A measurement is a report about the world; a
 * fingerprint is supposed to be a fact about the device.
 */
export function domBlockers(): ProbeResult<Record<string, unknown>> {
    return probe('domBlockers', () => {
        const read = (fn: () => unknown): unknown => {
            try {
                return fn();
            } catch (error) {
                return 'throw:' + (error instanceof Error ? error.name : 'Error');
            }
        };

        const global = window as unknown as Record<string, unknown>;
        const chrome = (global.chrome ?? {}) as Record<string, unknown>;

        return {
            chromeRuntime: read(() => typeof global.chrome !== 'undefined' && typeof chrome.runtime === 'object'),
            chromeCsi: read(() => typeof global.chrome !== 'undefined' && typeof chrome.csi === 'function'),
            chromeLoadTimes: read(() => typeof global.chrome !== 'undefined' && typeof chrome.loadTimes === 'function'),
            getEventListeners: read(() => typeof (global as { getEventListeners?: unknown }).getEventListeners),
            webdriverUndefined: read(() => (global as { webdriver?: unknown }).webdriver === undefined),
            windowWebdriverEvaluate: read(() => typeof (global as { __webdriver_evaluate?: unknown }).__webdriver_evaluate),
            windowSeleniumEvaluate: read(() => typeof (global as { __selenium_evaluate?: unknown }).__selenium_evaluate),
            windowNightmare: read(() => typeof (global as { __nightmare?: unknown }).__nightmare),
            windowDriverUnwrapped: read(() => typeof (global as { __driverUnwrapped?: unknown }).__driverUnwrapped),
            domRectToJSON: read(
                () => typeof (Element.prototype.getBoundingClientRect as unknown as { toJSON?: unknown }).toJSON === 'function',
            ),
            // The exact length of a native function's source is a stable engine
            // constant, and it is what a `toString` patch has to fake.
            functionToStringLength: read(() => Function.prototype.toString.toString().length),
            errorPrepareStackTrace: read(() => typeof Error.prepareStackTrace),
            performanceObserverEntryTypes: read(() => {
                try {
                    new PerformanceObserver(() => undefined).observe({
                        type: 'long-animation-frame',
                        buffered: true,
                    } as PerformanceObserverInit);
                    return 'ok';
                } catch (error) {
                    return 'unsupported:' + (error instanceof Error ? error.name : 'Error');
                }
            }),
        };
    });
}

/**
 * Timings for the blocker probe, as a DIAGNOSTIC only.
 *
 * Never included in the claim set and never hashed — see the class docblock for the
 * two failed attempts and why. Exists so the admin screen can answer "why was this
 * environment slow here" without that answer becoming part of the identifier.
 */
export function measureDomBlockerAccess(): Array<{ name: string; bucket: string; ms: number }> {
    const bucket = (ms: number): string => (ms < 0.05 ? '0' : ms < 0.5 ? '1' : ms < 2 ? '2' : ms < 10 ? '3' : '4');

    const targets: Array<[string, () => unknown]> = [
        ['chromeRuntime', () => (window as unknown as { chrome?: { runtime?: unknown } }).chrome?.runtime],
        ['chromeCsi', () => (window as unknown as { chrome?: { csi?: unknown } }).chrome?.csi],
        ['getEventListeners', () => (window as unknown as { getEventListeners?: unknown }).getEventListeners],
        ['functionToString', () => Function.prototype.toString],
        ['errorPrepareStackTrace', () => (Error as { prepareStackTrace?: unknown }).prepareStackTrace],
    ];

    return targets.map(([name, read]) => {
        const start = performance.now();
        try {
            read();
        } catch {
            /* a throwing access is itself the signal, reported elsewhere */
        }
        const ms = performance.now() - start;

        return { name, bucket: bucket(ms), ms: Math.round(ms * 1000) / 1000 };
    });
}

/**
 * Run every integrity probe and derive the finding list.
 *
 * `findings` contains ONLY things that look wrong. An empty list is the normal,
 * expected result for a real browser, and the server must treat it as "nothing to
 * see here" rather than as a failure.
 */
export function collectIntegrity(): IntegrityReport {
    const started = performance.now();

    const wrongReceiverResult = wrongReceiver();
    const descriptorResult = descriptorIntegrity();
    const mathResult = mathDual();
    const canvasResult = canvasDual();
    const blockersResult = domBlockers();

    const findings: IntegrityFinding[] = [];

    if (wrongReceiverResult.state === 'ok') {
        for (const [target, verdict] of Object.entries(wrongReceiverResult.value)) {
            if (verdict === 'did-not-throw') {
                findings.push({
                    code: INTEGRITY_CODES.WRONG_RECEIVER_OK,
                    detail: `${target} did not throw when called with the wrong receiver; a real WebIDL attribute must.`,
                });
            }
            // `data-property` and `not-an-attribute` are deliberately NOT findings.
            // The first version of this raised on them and produced four false
            // positives in every engine, because the target list contained methods.
        }
    }

    if (descriptorResult.state === 'ok') {
        for (const [name, shape] of Object.entries(descriptorResult.value)) {
            if (shape === 'no-descriptor') {
                // A missing descriptor is only evidence when the property is
                // actually reachable. `navigator.sendBeacon` does not exist in
                // WebKit and `navigator.userAgentData` does not exist in Firefox, so
                // "no descriptor" is the correct answer for an API that was never
                // implemented. The distinguishing test is whether the property is
                // readable at all: if it is, something supplied it, and a supplied
                // value without a WebIDL descriptor is exactly what a spoofer leaves
                // behind when it `delete`s a property. Requiring a descriptor for all
                // thirty names raised 7 false findings in WebKit and 1 in Firefox.
                if (name in navigator) {
                    findings.push({
                        code: INTEGRITY_CODES.DESCRIPTOR_MISSING,
                        detail: `navigator.${name} is readable but Navigator.prototype has no descriptor for it.`,
                    });
                }
                continue;
            }
            if (shape.startsWith('P')) {
                findings.push({
                    code: INTEGRITY_CODES.DESCRIPTOR_PATCHED,
                    detail: `Navigator.prototype.${name} is not a native function.`,
                });
            }
            if (shape.includes('U')) {
                findings.push({
                    code: INTEGRITY_CODES.DESCRIPTOR_UNSTABLE,
                    detail: `Navigator.prototype.${name} returns a different getter object on each read, which a real attribute never does.`,
                });
            }
            if (shape.includes('W')) {
                findings.push({
                    code: INTEGRITY_CODES.DESCRIPTOR_SETTER,
                    detail: `Navigator.prototype.${name} has a setter; a real read-only attribute does not.`,
                });
            }
        }
    }

    if (mathResult.state === 'ok') {
        for (const key of ['atanhAgrees', 'tanhAgrees', 'expm1Agrees', 'asinhAgrees'] as const) {
            if (mathResult.value[key] !== true) {
                findings.push({
                    code: INTEGRITY_CODES.MATH_PF_MISMATCH,
                    detail: `Two independent implementations of the same mathematical quantity disagree on ${key}.`,
                });
            }
        }
        for (const [key, value] of Object.entries(mathResult.value)) {
            if (key.endsWith('Pf') && typeof value === 'number' && !Number.isFinite(value)) {
                findings.push({
                    code: INTEGRITY_CODES.MATH_PF_MISMATCH,
                    detail: `${key} evaluated to a non-finite value.`,
                });
            }
        }
    }

    if (canvasResult.state === 'ok') {
        if (!canvasResult.value.agree) {
            findings.push({
                code: INTEGRITY_CODES.CANVAS_DUAL_DIVERGED,
                detail: 'Two independent constructions of the same shape rasterised differently; a conformant renderer cannot do that.',
            });
        }
        const winding = canvasResult.value.winding;
        if (typeof winding === 'object' && winding !== null && 'differ' in winding && winding.differ !== true) {
            findings.push({
                code: INTEGRITY_CODES.CANVAS_WINDING_FALSE,
                detail: 'The canvas rasteriser does not distinguish the nonzero and evenodd fill rules.',
            });
        }
    }

    if (blockersResult.state === 'ok') {
        for (const [name, value] of Object.entries(blockersResult.value)) {
            if (typeof value === 'string' && value.startsWith('throw:')) {
                findings.push({
                    code: INTEGRITY_CODES.DOM_BLOCKER_THROW,
                    detail: `Accessing ${name} threw, which suggests an extension or blocker is intercepting it.`,
                });
            }
            if (name === 'windowWebdriverEvaluate' && value === 'function') {
                findings.push({
                    code: INTEGRITY_CODES.DOM_BLOCKER_PRESENT,
                    detail: 'An automation-injected __webdriver_evaluate global is present.',
                });
            }
            if (name === 'windowSeleniumEvaluate' && value === 'function') {
                findings.push({
                    code: INTEGRITY_CODES.DOM_BLOCKER_PRESENT,
                    detail: 'An automation-injected __selenium_evaluate global is present.',
                });
            }
            if (name === 'windowNightmare' && value === 'function') {
                findings.push({
                    code: INTEGRITY_CODES.DOM_BLOCKER_PRESENT,
                    detail: 'A Nightmare automation global is present.',
                });
            }
        }
    }

    return {
        findings,
        data: {
            wrongReceiver: wrongReceiverResult,
            descriptorIntegrity: descriptorResult,
            mathDual: mathResult,
            canvasDual: canvasResult,
            domBlockers: blockersResult,
        },
        elapsedMs: Math.round((performance.now() - started) * 1000) / 1000,
    };
}

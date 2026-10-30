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
 * Ten probes. The first five measured 1.5-3 ms warm, about 9 ms cold (first canvas use),
 * in Chromium; `webdriverPresence` and `canvasFill` were added later, and `lieBattery`,
 * `phantomRealm` (phantom.ts) and `resistance` after them. Measured warm medians of those
 * three (Playwright headless, Chromium / Firefox / WebKit): `lieBattery` 1-2 ms everywhere,
 * `resistance` 0.2 / 2 / 2 ms, `phantomRealm` 16 / 25 / 11 ms — creating the iframe's realm
 * is nearly all of that (appending a bare `about:blank` iframe alone measured 4-15 / 9-21 /
 * 3-10 ms), so `phantomRealm` is by far the most expensive integrity probe and runs in the
 * DEFERRED phase (`collectDeferredIntegrity`), not in `collectIntegrity`. The
 * whole set's cost is printed per engine by tests/Browser/transport-checks.mjs.
 *
 * ## Per-method policy
 *
 * `collectIntegrity(disabled)` and `collectDeferredIntegrity(disabled)` skip every probe whose registry name (CONTRACT-2 §N:
 * mathDual, canvasDual, domBlockers, canvasFill, lieBattery, phantomRealm, resistance) is in
 * `disabled`: a skipped probe is ABSENT from `data` and raises nothing, because the server
 * knows its own policy and does not expect it. `wrongReceiver` and `descriptorIntegrity` are
 * core and run even when named (the server never sends them; the client defends anyway).
 * `webdriverPresence` is not a registry name, so no policy can skip it.
 *
 * ## What these catch, and what they do not
 *
 * The naive patch — a plain closure installed on `Navigator.prototype` — is caught.
 * An own property defined on the `navigator` INSTANCE is caught by the shadow check in
 * `descriptorIntegrity`. A brand-checking getter with a patched
 * `Function.prototype.toString`, and an engine-level override (CDP, Firefox prefs,
 * Camoufox), are NOT detectable from a late-loaded script; those belong to the
 * transport/JA4 side.
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
 *   right. The ONE exception is `phantomRealm` (phantom.ts): a hidden iframe attached and
 *   removed inside one synchronous call, for the reasons its docblock gives.
 * - **Never throw.** A throwing probe aborts the collection it is inside.
 */

import { probe, unavailable, type ProbeResult } from './canonical';
import { lieCodesOf } from './lies';
import { CORE_PROBES, type IntegrityFinding } from './protocol';
import { LIE_TARGETS, phantomRealm, resolveTarget, subValue, type LieTarget, type PhantomRealmValue } from './phantom';

// The native-function invariants live in lies.ts (no dependencies), so phantom.ts can use them
// without an import cycle; re-exported here, where they were first defined.
export { LIE_CODES, lieCodesOf, type LieCode } from './lies';
import { classifyEngine, engineMarks } from './realm';

/** Verdict codes. Stable strings: the server stores and indexes them. */
export const INTEGRITY_CODES = {
    WRONG_RECEIVER_OK: 'wrong_receiver_did_not_throw',
    WRONG_RECEIVER_DATA_PROPERTY: 'wrong_receiver_data_property',
    WRONG_RECEIVER_NO_DESCRIPTOR: 'wrong_receiver_no_descriptor',
    DESCRIPTOR_PATCHED: 'descriptor_patched',
    DESCRIPTOR_UNSTABLE: 'descriptor_unstable',
    DESCRIPTOR_MISSING: 'descriptor_missing',
    DESCRIPTOR_SETTER: 'descriptor_has_setter',
    DESCRIPTOR_SHADOWED: 'descriptor_shadowed',
    MATH_PF_MISMATCH: 'math_pf_mismatch',
    CANVAS_DUAL_DIVERGED: 'canvas_dual_diverged',
    CANVAS_WINDING_FALSE: 'canvas_winding_false',
    DOM_BLOCKER_THROW: 'dom_blocker_threw',
    DOM_BLOCKER_PRESENT: 'dom_blocker_present',
    WEBDRIVER_MISSING: 'webdriver_missing',
    CANVAS_READBACK_PERTURBED: 'canvas_readback_perturbed',
    LIE_BATTERY_FAILED: 'lie_battery_failed',
    REALM_TOSTRING_MISMATCH: 'realm_tostring_mismatch',
    DOMRECT_INCONSISTENT: 'domrect_inconsistent',
    SVG_TEXT_INCONSISTENT: 'svg_text_inconsistent',
} as const;

/**
 * One finding on the wire: its code, nothing else (protocol.ts `IntegrityFinding`). The
 * client used to attach an English `detail` sentence; the server never read it (it lifts
 * findings by code and writes its own sentence), so it was ~1.7 KB of shipped prose that
 * explained each check, and attacker-controllable free text on the wire. One entry per
 * occurrence is kept: the server's integrity penalty counts entries.
 */
export type { IntegrityFinding };

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

        // Attributes only: WebIDL attributes, plus the ECMA-402 `format` getter, which
        // also brand-checks. `resolvedOptions` is a method and was dropped from the list.
        const scopes: Record<string, { proto: object; names: string[] }> = {
            screen: { proto: Screen.prototype, names: ['width', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'] },
            navigator: { proto: Navigator.prototype, names: ['userAgent', 'language', 'onLine', 'maxTouchPoints', 'hardwareConcurrency'] },
            intl: { proto: Intl.DateTimeFormat.prototype, names: ['format'] },
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
 * - descriptor presence: deleting `webdriver` is the oldest trick in the book. It is
 *   caught here as `descriptor_missing`, and the server's `webdriver_missing` rule
 *   (EnvironmentConsistency) catches it a second time from the claim set, so a client
 *   that strips this finding still does not pass.
 * - setter presence: a real read-only WebIDL attribute has no setter. A spoofer
 *   adding one is trying to make the property writable and is not subtle about it.
 * - instance shadowing: `Object.defineProperty(navigator, 'userAgent', {value})` leaves
 *   the prototype pristine and was the cheapest measured bypass. WebIDL attributes live
 *   on the prototype, so an own property on the instance is never legitimate.
 *
 * Shape string: native N/P, stable S/U, setter W/-, configurable c/C, enumerable e/-,
 * shadowed o/-.
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
            const shadowed = Object.prototype.hasOwnProperty.call(navigator, name);

            out[name] = [
                native ? 'N' : 'P',
                stable ? 'S' : 'U',
                first.set !== undefined ? 'W' : '-',
                first.configurable ? 'c' : 'C',
                first.enumerable ? 'e' : '-',
                shadowed ? 'o' : '-',
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

/** What `canvasDual` reports when the canvas read-back is trustworthy. */
export interface CanvasDualValue {
    readonly agree: boolean;
    readonly fillHash: string;
    readonly putHash: string;
    readonly winding: unknown;
}

/** Internal marker: two identical draws read back differently. Never on the wire. */
const CANVAS_RANDOMISED = Symbol('canvas-randomised');

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
 *
 * ## A randomised read-back is `unavailable`, never a finding (round-1 BR-5)
 *
 * Firefox `resistFingerprinting`, Tor Browser and per-read noise extensions
 * (CanvasBlocker) return different pixels from every `getImageData` call. Two reads then
 * always "disagree", and the first version reported `canvas_dual_diverged` on every load
 * of every such browser (measured: Firefox 142 + RFP, 6/6 loads), scoring a privacy
 * protection as tampering. So the same `fillRect` is drawn on a SECOND canvas first and
 * the two read-backs are compared: identical drawing must give identical pixels, so a
 * difference means the read-back is randomised, the probe reports
 * `unavailable: 'randomised'`, and no finding is emitted — the server's rule that absence
 * is not evidence then applies. Per-session noise (Brave farbling, Firefox FPP) is
 * deterministic for identical input, so it passes this check and both duals still agree.
 * Not solved here: under RFP the read itself raises Firefox's canvas permission prompt.
 */
export function canvasDual(): ProbeResult<CanvasDualValue> {
    const measured = probe('canvasDual', (): CanvasDualValue | typeof CANVAS_RANDOMISED => {
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

        // --- randomisation check: the SAME fillRect on a second canvas ---
        const canvasRepeat = document.createElement('canvas');
        canvasRepeat.width = W;
        canvasRepeat.height = H;
        const ctxRepeat = canvasRepeat.getContext('2d', { willReadFrequently: true });
        if (!ctxRepeat) throw new Error('no 2d context');
        ctxRepeat.fillStyle = '#123456';
        ctxRepeat.fillRect(7, 11, 41, 23);
        if (hashPixels(ctxRepeat) !== fillHash) return CANVAS_RANDOMISED;

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

    if (measured.state !== 'ok') return measured;

    return measured.value === CANVAS_RANDOMISED ? unavailable('randomised') : { state: 'ok', value: measured.value };
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
            // The attribute is `navigator.webdriver`; a deleted one reads undefined.
            webdriverUndefined: read(() => navigator.webdriver === undefined),
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
            // `observe()` with an unknown type does not throw: the engine logs a console
            // warning and ignores it. `supportedEntryTypes` is the silent form of the
            // same question.
            performanceObserverEntryTypes: read(() => {
                if (typeof PerformanceObserver !== 'function') return 'absent';
                const types = (PerformanceObserver as { supportedEntryTypes?: readonly string[] }).supportedEntryTypes;
                if (!Array.isArray(types)) return 'no-list';
                return types.includes('long-animation-frame') ? 'ok' : 'unsupported';
            }),
        };
    });
}

/**
 * Probe 6 — is `navigator.webdriver` there at all?
 *
 * Every engine in the supported matrix has shipped the attribute for years. BCD 8.1.4
 * (`api.Navigator.webdriver`, read from the repository's own `@mdn/browser-compat-data`):
 * Chrome 63, Edge 12, Firefox 60, Safari 10.1, Chrome Android 63, Firefox Android 60,
 * Safari iOS 10.3, WebView Android 63, Samsung Internet 8.0. The project's floor
 * (`package.json` browserslist) is Chrome/Edge 111, Firefox 111 and Safari 16.4, so on
 * every supported browser `'webdriver' in navigator` is true, and it reads `false` when
 * the browser is not automated.
 *
 * Deleting it is the classic stealth evasion: an automation flag that reads `true` is
 * obvious, so stealth plugins remove the attribute instead, and a removed attribute is
 * absent from `navigator` AND from `Navigator.prototype`. That is why this checks the
 * `in` operator and not the value: `navigator.webdriver === undefined` (kept, as data,
 * in `domBlockers.webdriverUndefined`) cannot tell a deletion from a getter returning
 * `undefined`, and `descriptorIntegrity` only raises `descriptor_missing` when the name
 * is still reachable — a full deletion makes it unreachable, so neither existing probe
 * produced a finding for it.
 *
 * Prior art: CreepJS `webDriverIsOn` (catalogue §4, `headless`) — it gates the check on
 * `CSS.supports('border-end-end-radius: initial')`, i.e. Chrome 89+, as the release from
 * which an unautomated Chrome exposes the attribute. That gate is CreepJS's reading and is
 * not verified here; it is below the project's floor either way, so no gate is applied. A
 * visitor on a browser older than the supported matrix may legitimately lack the
 * attribute, which is a server-side weighting question.
 */
export function webdriverPresence(): ProbeResult<{ present: boolean }> {
    return probe('webdriverPresence', () => ({ present: 'webdriver' in navigator }));
}

/** What `canvasFill` reports. */
export interface CanvasFillValue {
    /** Every read pixel is exactly (10, 20, 30, 255). */
    readonly exact: boolean;
    /** How many of the 62×62 read pixels are not. */
    readonly deviations: number;
}

/** Internal marker: no 2D context. Never on the wire. */
const NO_2D_CONTEXT = Symbol('no-2d-context');

/**
 * Probe 7 — a canvas read-back against a value known a priori.
 *
 * A 64×64 canvas is filled with the opaque colour `rgb(10,20,30)` and the inner 62×62 is
 * read back. The specification fixes the answer: an opaque `fillRect` covering whole
 * pixels in the sRGB canvas writes exactly that colour, with no antialiasing (the
 * rectangle is pixel-aligned) and no premultiplication loss (alpha is 255). Every pixel
 * must read (10, 20, 30, 255). There is no table and nothing engine-specific: the true
 * value is the input.
 *
 * What it catches that `canvasDual` cannot: deterministic per-session noise (Brave's
 * farbling, Firefox's fingerprinting protection, extensions that seed noise per session)
 * returns the SAME perturbed pixels for the same drawing, so `canvasDual`'s repeat-render
 * check sees two identical reads and passes. Here the reference is the specified value, not
 * a second read, so any noise at all shows. Per-read randomisation shows too.
 *
 * The inner region (1..62) is read rather than the full canvas so a renderer that treats
 * the outermost pixel row differently cannot produce a finding; the fill covers the whole
 * canvas, so every read pixel is interior.
 *
 * No 2D context → `unavailable('no-2d-context')`, never a finding. A `getImageData` that
 * throws → `error`, never a finding.
 *
 * Note for the server: the finding means "the read-back is not what was drawn". Privacy
 * protections produce it as well as spoofers, so it says the canvas read-back cannot be
 * trusted, not who is responsible.
 */
export function canvasFill(): ProbeResult<CanvasFillValue> {
    const measured = probe('canvasFill', (): CanvasFillValue | typeof NO_2D_CONTEXT => {
        const canvas = document.createElement('canvas');
        canvas.width = 64;
        canvas.height = 64;
        const context = canvas.getContext('2d', { willReadFrequently: true });
        if (!context) return NO_2D_CONTEXT;

        context.fillStyle = 'rgb(10,20,30)';
        context.fillRect(0, 0, 64, 64);
        const data = context.getImageData(1, 1, 62, 62).data;

        let deviations = 0;
        for (let i = 0; i < data.length; i += 4) {
            if (data[i] !== 10 || data[i + 1] !== 20 || data[i + 2] !== 30 || data[i + 3] !== 255) {
                deviations++;
            }
        }
        // A short read (fewer bytes than 62×62 pixels) is a deviation too: the missing
        // pixels were not read back as drawn.
        deviations += Math.max(0, 62 * 62 - Math.floor(data.length / 4));

        return { exact: deviations === 0, deviations };
    });

    if (measured.state !== 'ok') return measured;

    return measured.value === NO_2D_CONTEXT
        ? unavailable('no-2d-context')
        : { state: 'ok', value: measured.value };
}

// ---------------------------------------------------------------------------
// Probe 8 — the lie battery
// ---------------------------------------------------------------------------

/** What `lieBattery` reports. */
export interface LieBatteryValue {
    /** How many targets were inspected (absent APIs are not counted). */
    readonly checked: number;
    /** `api` → its violated codes, comma-joined in `LIE_CODES` order. Only apis with at least one code. */
    readonly lied: Readonly<Record<string, string>>;
}


/**
 * Probe 8 — the lie battery (contract §I1; CreepJS `src/lies`, catalogue §1).
 *
 * Every target in `LIE_TARGETS` (phantom.ts) is put through eight invariants that a native
 * function satisfies in every engine — measured: all 25 targets in Chromium and all 24 in
 * Firefox and WebKit pass all eight, so none had to be dropped or narrowed:
 *
 * | code | invariant | catches |
 * |---|---|---|
 * | `new_instance` | `new fn()` throws TypeError | a `function` closure (constructible) |
 * | `prototype_in` | `'prototype' in fn` is false | a `function` closure or class |
 * | `own_keys` | own property names are exactly `length,name` | extra own props (a patched `toString`, sloppy `arguments`) |
 * | `descriptor_keys` | own descriptor keys are exactly `length,name` | the same, through a different reflection path |
 * | `to_string` | source is `function [get ]<name>() { [native code] }` | any JS-defined function, a bound function, a V8 Proxy |
 * | `object_to_string` | `Object.create(fn).toString()` throws TypeError | an own or lenient `toString` that accepts a non-function |
 * | `proto_cycle` | a cyclic `setPrototypeOf` throws TypeError | a `Proxy` wrapper (see `protoCycleLies`) |
 * | `arguments_access` | reading `fn.arguments` throws TypeError | a sloppy-mode closure, a Proxy `get` trap |
 *
 * Differences from CreepJS, deliberately: no stack-text or error-message regexes (CreepJS
 * matches `/at Function\.toString /` on Blink and `/strict mode/` on Gecko, which are
 * engine-version specific and were not needed — every invariant above is an engine-neutral
 * TypeError-or-not question); no `class extends` check (CreepJS skips it on WebKit); and the
 * toString check also requires the source's NAME to be the member's name, which CreepJS's
 * exact-string table does too but this does with one pattern for all three engines' layouts.
 *
 * ## The finding: every code counts, `to_string` included
 *
 * `lie_battery_failed` fires when any target violates any code. Contract §I1 first excluded
 * `to_string`-only cases, attributing that to CreepJS; but CreepJS's own exclusion
 * (`getNonFunctionToStringLies`) is of its `object toString` and `toString incompatible
 * proxy` lies, not of `failed toString`. With the exclusion, an arrow function, a method
 * shorthand (`get userAgent() {}`) or a bound function installed as a replacement violated
 * ONLY `to_string` and raised nothing — invisible on every non-Navigator target. The
 * exclusion was dropped (coordinator decision). The `to_string` pattern is safe to count
 * because it was measured on every target in all three engines, name included.
 *
 * Consequence under jsdom (tests only): jsdom's WebIDL getters are JavaScript, so plain jsdom
 * raises `lie_battery_failed` on them — exactly as it raises `webdriver_missing`.
 *
 * ## Side effects
 *
 * None on a native function: `new fn()` throws before the body runs (natives are not
 * constructors), the prototype-cycle attempt throws before mutating, and every other
 * invariant is a read. On a NON-native replacement, `new fn()` runs the replacement's own
 * code (as CreepJS does) and the proto-cycle attempt is repaired at once.
 */
export function lieBattery(targets: readonly LieTarget[] = LIE_TARGETS): ProbeResult<LieBatteryValue> {
    return probe('lieBattery', () => {
        let checked = 0;
        const lied: Record<string, string> = {};

        for (const target of targets) {
            const fn = resolveTarget(target);
            if (fn === null) continue;
            checked++;

            const codes = lieCodesOf(fn, target.api.slice(target.api.lastIndexOf('.') + 1));
            if (codes.length > 0) {
                lied[target.api] = codes.join(',');
            }
        }

        return { checked, lied };
    });
}

// ---------------------------------------------------------------------------
// Probe 10 — privacy-tool resistance (no finding)
// ---------------------------------------------------------------------------

/** What `resistance` reports. Never a finding: a privacy tool is an honest visitor. */
export interface ResistanceValue {
    /** `navigator.brave.isBrave` is a function. Null only when reading it threw. */
    readonly brave: boolean | null;
    /** The `performance.now()` tick in microseconds (see `timerGranularityUs`). */
    readonly timerGranularityUs: number | null;
    /** Gecko AND a timer tick of at least 10 ms: Firefox `resistFingerprinting` or Tor Browser. */
    readonly rfp: boolean;
    /** Gecko AND `RTCRtpTransceiver`, `MediaDevices` and `Credential` all undefined. */
    readonly tor: boolean;
    /** The engine marks classify this realm as SpiderMonkey (realm.ts `classifyEngine`). */
    readonly gecko: boolean;
}

/** Upper bound on `performance.now()` reads in `timerGranularityUs`. */
export const TIMER_SPIN_CAP = 50_000;

/**
 * Lower bound on reads, whatever the crossings. With an UNCLAMPED clock (Node, which runs the
 * jsdom suite) every read is a crossing, and the first reads run in the interpreter, so two
 * crossings would sample the slowest deltas of the loop and round to 0 or 1 µs depending on
 * warm-up. Sixty-four reads make the minimum the loop's steady state (0 µs there). In a
 * browser they take tens of microseconds, far less than one clamped tick.
 */
const TIMER_MIN_READS = 64;

/** Coarse ticks recognised when no tick boundary was crossed inside the spin: Tor's 100 ms, RFP's 1/60 s. */
const COARSE_TICKS_US = [100_000, 16_667] as const;

/**
 * The `performance.now()` tick, in microseconds: the smallest positive difference between
 * consecutive distinct readings, read until two tick boundaries have been crossed (and at
 * least `TIMER_MIN_READS` reads made) or `TIMER_SPIN_CAP` reads have been made.
 *
 * ## Why not "2000 spins", as first specified
 *
 * Measured: 2000 reads take 0 ms in Firefox and 1 ms in WebKit, whose ticks are 1 ms — so
 * Firefox crossed NO boundary in 2000 reads (null) and WebKit crossed zero or one depending on
 * phase. The value would then differ between two loads of the same browser, which the
 * stable-claims check (c) forbids for anything in `integrity.data`. Reading until two
 * boundaries are crossed makes it exact and repeatable: every observed delta is a whole tick,
 * so the minimum is the tick (Chromium 100, Firefox 1000, WebKit 1000, measured on every
 * load). Two rather than one so a single read pre-empted across a boundary (a 2-tick delta)
 * cannot decide the value. Cost: at most two ticks of spinning — ≈0.2 ms in Chromium, ≤2 ms
 * in Firefox and WebKit.
 *
 * ## Coarse timers
 *
 * Firefox with `privacy.resistFingerprinting` ticks every 16.667 ms (measured: readings
 * 316.673, 333.340, 350.007 ms) and Tor Browser every 100 ms; spinning for two of those would
 * cost 33-200 ms on the critical path. So the spin is capped (50 000 reads, ≈5 ms at the
 * ~100 ns per read measured in stock Firefox and WebKit), and when it
 * ends with one boundary crossed that delta is the tick. When it ends with none, the single
 * reading is tested for being a whole multiple of a known coarse tick: RFP readings are exact
 * multiples of 16 667 µs, Tor's of 100 000 µs, and the two are coprime, so neither is mistaken
 * for the other. A reading that is neither, or 0, gives null ("not measured").
 *
 * `now` is injectable so the arithmetic can be tested with a scripted clock.
 */
export function timerGranularityUs(now: () => number = () => performance.now()): number | null {
    let last = now();
    let smallest = Number.POSITIVE_INFINITY;
    let crossings = 0;

    for (let i = 0; i < TIMER_SPIN_CAP && (crossings < 2 || i < TIMER_MIN_READS); i++) {
        const current = now();
        if (current !== last) {
            if (current > last) {
                smallest = Math.min(smallest, current - last);
                crossings++;
            }
            last = current;
        }
    }

    if (crossings > 0) {
        return Math.round(smallest * 1000);
    }

    const reading = Math.round(last * 1000);
    if (!Number.isFinite(reading) || reading <= 0) {
        return null;
    }

    return COARSE_TICKS_US.find((tick) => reading % tick === 0) ?? null;
}

/** Granularity at or above which a Gecko timer counts as RFP-clamped. */
const RFP_MIN_TICK_US = 10_000;

/**
 * Probe 10 — Brave, Firefox `resistFingerprinting` and Tor Browser (contract §I3; CreepJS
 * `src/resistance`, catalogue §3). Synchronous, and NEVER a finding: these identify a privacy
 * tool, and a privacy tool is an honest visitor. The server's per-component trust reads it
 * (a farbled canvas from a known Brave is expected; the same from "Chrome" is not).
 *
 * - `brave`: `navigator.brave.isBrave` is a function. `isBrave()` is NOT awaited: the
 *   object's presence is the mark, and the call is async.
 * - `gecko`: from the engine marks in realm.ts, not from `typeof InstallTrigger` (CreepJS's
 *   test): measured, reading `InstallTrigger` in Firefox logs "InstallTrigger is deprecated"
 *   to the console, which the collector must never cause.
 * - `rfp`: Gecko and a tick of at least 10 ms. Measured: stock Playwright Firefox ticks at
 *   1 ms, the same browser with `privacy.resistFingerprinting` at 16.667 ms.
 * - `tor`: Gecko and `RTCRtpTransceiver`, `MediaDevices` and `Credential` all undefined
 *   (CreepJS's rule). Measured: Credential is undefined in Playwright's WebKit, which is why
 *   the Gecko gate is not optional.
 *
 * CreepJS's timer test is different (`+new Date()` at ten `setTimeout` delays, asynchronous);
 * the synchronous spin is used because this probe runs inside the synchronous integrity
 * phase.
 */
export function resistance(): ProbeResult<ResistanceValue> {
    return probe('resistance', () => {
        let brave: boolean | null;
        try {
            const mark = (navigator as unknown as { brave?: { isBrave?: unknown } }).brave;
            brave = typeof mark === 'object' && mark !== null && typeof mark.isBrave === 'function';
        } catch {
            brave = null;
        }

        const timerGranularity = timerGranularityUs();
        const gecko = classifyEngine(engineMarks()) === 'spidermonkey';
        const globals = globalThis as Record<string, unknown>;
        const tor =
            gecko &&
            typeof globals.RTCRtpTransceiver === 'undefined' &&
            typeof globals.MediaDevices === 'undefined' &&
            typeof globals.Credential === 'undefined';

        return {
            brave,
            timerGranularityUs: timerGranularity,
            rfp: gecko && timerGranularity !== null && timerGranularity >= RFP_MIN_TICK_US,
            tor,
            gecko,
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
 * Probes the policy can never switch off: the one shared list, `CORE_PROBES` (protocol.ts),
 * which names `wrongReceiver`, `descriptorIntegrity` and `resistance` among the integrity
 * probes. The server never names them in its disabled list; this is the client's defence if
 * it ever did.
 */
const CORE_INTEGRITY_PROBES: ReadonlySet<string> = new Set(CORE_PROBES);

/**
 * Run every integrity probe and derive the finding list.
 *
 * `findings` contains ONLY things that look wrong. An empty list is the normal,
 * expected result for a real browser, and the server must treat it as "nothing to
 * see here" rather than as a failure.
 *
 * `disabled` is the server's per-method policy (registry names). A disabled probe is not
 * run, is absent from `data` and raises nothing; unknown names are ignored, and the core
 * probes run regardless. Never throws, whatever `disabled` holds.
 */
export function collectIntegrity(disabled: readonly string[] = []): IntegrityReport {
    const started = performance.now();

    const run = policyRunner(disabled);

    const wrongReceiverResult = run('wrongReceiver', wrongReceiver);
    const descriptorResult = run('descriptorIntegrity', descriptorIntegrity);
    const mathResult = run('mathDual', mathDual);
    const canvasResult = run('canvasDual', canvasDual);
    const blockersResult = run('domBlockers', domBlockers);
    // Not a registry name: no policy can skip it.
    const webdriverResult = webdriverPresence();
    const canvasFillResult = run('canvasFill', canvasFill);
    const lieBatteryResult = run('lieBattery', () => lieBattery());
    const resistanceResult = run('resistance', resistance);

    const findings: IntegrityFinding[] = [];

    if (wrongReceiverResult?.state === 'ok') {
        for (const verdict of Object.values(wrongReceiverResult.value)) {
            if (verdict === 'did-not-throw') {
                findings.push({ code: INTEGRITY_CODES.WRONG_RECEIVER_OK });
            }
            // `data-property` and `not-an-attribute` are deliberately NOT findings.
            // The first version of this raised on them and produced four false
            // positives in every engine, because the target list contained methods.
        }
    }

    if (descriptorResult?.state === 'ok') {
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
                    findings.push({ code: INTEGRITY_CODES.DESCRIPTOR_MISSING });
                }
                continue;
            }
            if (shape.startsWith('P')) {
                findings.push({ code: INTEGRITY_CODES.DESCRIPTOR_PATCHED });
            }
            if (shape.includes('U')) {
                findings.push({ code: INTEGRITY_CODES.DESCRIPTOR_UNSTABLE });
            }
            if (shape.includes('W')) {
                findings.push({ code: INTEGRITY_CODES.DESCRIPTOR_SETTER });
            }
            if (shape.endsWith('o')) {
                findings.push({ code: INTEGRITY_CODES.DESCRIPTOR_SHADOWED });
            }
        }
    }

    if (mathResult?.state === 'ok') {
        for (const key of ['atanhAgrees', 'tanhAgrees', 'expm1Agrees', 'asinhAgrees'] as const) {
            if (mathResult.value[key] !== true) {
                findings.push({ code: INTEGRITY_CODES.MATH_PF_MISMATCH });
            }
        }
        for (const [key, value] of Object.entries(mathResult.value)) {
            if (key.endsWith('Pf') && typeof value === 'number' && !Number.isFinite(value)) {
                findings.push({ code: INTEGRITY_CODES.MATH_PF_MISMATCH });
            }
        }
    }

    if (canvasResult?.state === 'ok') {
        if (!canvasResult.value.agree) {
            findings.push({ code: INTEGRITY_CODES.CANVAS_DUAL_DIVERGED });
        }
        const winding = canvasResult.value.winding;
        if (typeof winding === 'object' && winding !== null && 'differ' in winding && winding.differ !== true) {
            findings.push({ code: INTEGRITY_CODES.CANVAS_WINDING_FALSE });
        }
    }

    if (blockersResult?.state === 'ok') {
        for (const [name, value] of Object.entries(blockersResult.value)) {
            if (typeof value === 'string' && value.startsWith('throw:')) {
                findings.push({ code: INTEGRITY_CODES.DOM_BLOCKER_THROW });
            }
            if (name === 'windowWebdriverEvaluate' && value === 'function') {
                findings.push({ code: INTEGRITY_CODES.DOM_BLOCKER_PRESENT });
            }
            if (name === 'windowSeleniumEvaluate' && value === 'function') {
                findings.push({ code: INTEGRITY_CODES.DOM_BLOCKER_PRESENT });
            }
            if (name === 'windowNightmare' && value === 'function') {
                findings.push({ code: INTEGRITY_CODES.DOM_BLOCKER_PRESENT });
            }
        }
    }

    if (webdriverResult.state === 'ok' && !webdriverResult.value.present) {
        findings.push({ code: INTEGRITY_CODES.WEBDRIVER_MISSING });
    }

    if (canvasFillResult?.state === 'ok' && !canvasFillResult.value.exact) {
        findings.push({ code: INTEGRITY_CODES.CANVAS_READBACK_PERTURBED });
    }

    if (lieBatteryResult?.state === 'ok') {
        // Every lie code counts (coordinator decision, superseding contract §I1's `to_string`
        // exclusion), so any api in `lied` raises the finding. Which apis lied, and how, is in
        // `data.lieBattery.lied`, which the server reads.
        if (Object.keys(lieBatteryResult.value.lied).length > 0) {
            findings.push({ code: INTEGRITY_CODES.LIE_BATTERY_FAILED });
        }
    }

    // `resistance` raises nothing by design: it identifies privacy tools, not tampering.

    const entries: Array<[string, ProbeResult<unknown> | undefined]> = [
        ['wrongReceiver', wrongReceiverResult],
        ['descriptorIntegrity', descriptorResult],
        ['mathDual', mathResult],
        ['canvasDual', canvasResult],
        ['domBlockers', blockersResult],
        ['webdriverPresence', webdriverResult],
        ['canvasFill', canvasFillResult],
        ['lieBattery', lieBatteryResult],
        ['resistance', resistanceResult],
    ];

    return report(findings, entries, started);
}

/**
 * The DEFERRED integrity phase, run in idle time after the tier-1 envelope is away (the
 * caller, index.ts, decides when).
 *
 * ## Why there are two phases
 *
 * `phantomRealm` creates a fresh iframe realm, and that alone measured 4-15 / 9-21 / 3-10 ms
 * (Chromium / Firefox / WebKit, headless) — warm `collect()` went to 27 / 61 / 31 ms against a
 * 30 ms budget with it in the synchronous phase. So it moved here; nothing else did.
 *
 * ## What runs here, in this order
 *
 * 1. `phantomRealm` — findings (`realm_tostring_mismatch`, `domrect_inconsistent`,
 *    `svg_text_inconsistent`) and data, exactly as it reported in the synchronous phase before.
 * 2. `resistance` — data only; it never raises a finding.
 * 3. `canvasFill` AGAIN — data only, and deliberately NO finding: the synchronous phase already
 *    raised `canvas_readback_perturbed`, and raising it twice would double-count one fact.
 *
 * `resistance` and `canvasFill` are re-measured (≈1-3 ms in idle time) because the server
 * scores each envelope on its own: the tier-2 envelope carries the font, emoji and script
 * values, and deciding which of those components to trust needs `resistance` (a privacy
 * tool) and `canvasFill.exact` (a perturbed read-back) present in THAT envelope.
 *
 * Same shape and policy as `collectIntegrity`: a disabled name is absent from `data` and
 * raises nothing. Never throws.
 */
export function collectDeferredIntegrity(disabled: readonly string[] = []): IntegrityReport {
    const started = performance.now();
    const run = policyRunner(disabled);

    const phantomResult = run('phantomRealm', () => phantomRealm());
    const resistanceResult = run('resistance', resistance);
    const canvasFillResult = run('canvasFill', canvasFill);

    const findings: IntegrityFinding[] = phantomResult?.state === 'ok' ? phantomFindings(phantomResult.value) : [];
    // No canvas_readback_perturbed here: see the docblock (raised once, by the sync phase).

    return report(
        findings,
        [
            ['phantomRealm', phantomResult],
            ['resistance', resistanceResult],
            ['canvasFill', canvasFillResult],
        ],
        started,
    );
}

/** Run a probe unless the policy disables it; core probes always run. */
function policyRunner(disabled: readonly string[]): <T>(name: string, fn: () => ProbeResult<T>) => ProbeResult<T> | undefined {
    const off = new Set<string>(Array.isArray(disabled) ? disabled.filter((name): name is string => typeof name === 'string') : []);

    return <T>(name: string, fn: () => ProbeResult<T>): ProbeResult<T> | undefined =>
        CORE_INTEGRITY_PROBES.has(name) || !off.has(name) ? fn() : undefined;
}

/** Assemble a report; skipped probes (undefined) are left out of `data`. */
function report(findings: IntegrityFinding[], entries: Array<[string, ProbeResult<unknown> | undefined]>, started: number): IntegrityReport {
    const data: Record<string, ProbeResult<unknown>> = {};
    for (const [name, result] of entries) {
        if (result !== undefined) data[name] = result;
    }

    return { findings, data, elapsedMs: Math.round((performance.now() - started) * 1000) / 1000 };
}

/**
 * The findings the phantom realm's sub-results raise, by code only; which checks and apis
 * failed is in the sub-results themselves (`data.phantomRealm`). `screenTruth` raises nothing
 * (the server's `screen_vs_css_media` rule decides it), and a `realm-tampered` nativeToString
 * raises nothing either: it is `unavailable`, which is never evidence.
 */
export function phantomFindings(value: PhantomRealmValue): IntegrityFinding[] {
    const findings: IntegrityFinding[] = [];

    const toString = subValue(value.nativeToString);
    if (toString !== null && toString.mismatched.length > 0) {
        findings.push({ code: INTEGRITY_CODES.REALM_TOSTRING_MISMATCH });
    }

    const rect = subValue(value.domRect);
    // Any of the three equations failing: right-left/bottom-top arithmetic, identical
    // elements measuring identically, a 0x0 element measuring 0x0.
    if (rect !== null && !(rect.math && rect.identical && rect.ghost)) {
        findings.push({ code: INTEGRITY_CODES.DOMRECT_INCONSISTENT });
    }

    const svg = subValue(value.svgText);
    // Repeated getComputedTextLength reads disagree, or getBBox width disagrees with the length.
    if (svg !== null && !(svg.repeatEqual && svg.bboxAgrees)) {
        findings.push({ code: INTEGRITY_CODES.SVG_TEXT_INCONSISTENT });
    }

    return findings;
}

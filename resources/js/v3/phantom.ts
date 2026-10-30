/**
 * The lie-battery target list, and `phantomRealm`: one transient same-origin iframe that
 * hosts four integrity checks and one OS signal.
 *
 * ## Why an iframe, and why only here
 *
 * The rest of the collector never touches the DOM (integrity.ts, "Constraints"). This file
 * is the single, deliberate exception, made because two of the checks below are not
 * possible without a second realm or a laid-out document:
 *
 * - A page that patches `Function.prototype.toString` to make its replacement getters read
 *   `[native code]` defeats every source-text check that uses the PAGE's toString. A fresh
 *   realm's toString is a different function object that the patch never reached, and it
 *   describes the same page function honestly.
 * - Element geometry and SVG text metrics only exist for elements that are in a rendered
 *   document. Putting the measured elements in the PAGE would be a visible mutation of the
 *   page's own markup; putting them in a throwaway document is not.
 *
 * The exception is narrow and mechanical: one `<iframe>` (0×0, off-screen, hidden,
 * `aria-hidden`, out of the tab order) is appended to `document.documentElement` — not
 * `body`, which a page's own layout and its MutationObserver-driven frameworks watch more
 * often — used SYNCHRONOUSLY, and removed in a `finally` before `phantomRealm()` returns.
 * No event-loop turn passes while it is attached, so the page never renders a frame with it
 * and no page TASK runs against it. Page code CAN still run while it is attached: appending an
 * `about:blank` iframe dispatches its `load` event synchronously, so a capture-phase `load`
 * listener on the document runs during the append — early enough to patch the new realm's
 * `Function.prototype.toString` before it is read. That is why `nativeToString` first checks
 * the realm's own `toString` (`realmToStringTampered`) and reports
 * `unavailable('realm-tampered')` rather than agreement when it is not pristine. A page
 * MutationObserver also receives the add and the remove record afterwards. `about:blank` gives a realm
 * and a parsed document synchronously on append, measured in Chromium, Firefox and WebKit
 * (`readyState` 'complete', `<head>` and `<body>` present, `contentWindow` non-null).
 *
 * Every style is applied through the CSSOM (`element.style.cssText`, a constructed
 * `CSSStyleSheet`), never through a `<style>` element or a `style` attribute, so the iframe
 * keeps working if the inherited CSP ever drops `'unsafe-inline'` from `style-src`: CSP does
 * not govern CSSOM writes.
 *
 * ## Prior art: CreepJS, and what is done differently
 *
 * CreepJS (catalogue §1, `src/lies/index.ts`) builds the same kind of "phantom" iframe and
 * calls `scope.Function.prototype.toString.call(apiFunction)` from it; §19 (`src/domrect`)
 * checks rect arithmetic, identical elements and a 0×0 "ghost" element in it; §20
 * (`src/svg`) measures SVG text in it; §10 (`src/cssmedia`) evaluates media features through
 * an injected `@media` rule and a custom property; §9 (`src/css`) reads system fonts and
 * colours. The differences, each deliberate:
 *
 * - CreepJS leaves its phantom attached for the life of the page (and on Blink nests a
 *   second one). Here it lives for one synchronous call.
 * - CreepJS's DOMRect "known rotate" check compares against a hash recorded on one Blink and
 *   one Gecko build at DPR 1, which the catalogue notes false-positives elsewhere. Nothing
 *   here is compared with a recorded value: every check is an equation the engine's own
 *   output must satisfy (right − left = width, two identical elements measure identically,
 *   a 0×0 box at the origin is all zeros). The geometry sum is reported as data, not judged.
 * - CreepJS's `screenQuery` runs up to ten thousand `@media` rules to binary-search the true
 *   device size. This asks one question per dimension — "is the reported value the CSS
 *   value?" — plus a calibration rule (see `screenTruth`), and leaves the verdict to the
 *   server rule `screen_vs_css_media`.
 * - CreepJS hashes its 38 system colours and 6 system fonts into its identifier. A first
 *   version here reported the fonts and 8 colours as hashes; that sub-result was removed
 *   (five-review round): nothing consumed it, and it was one more OS-identifying value sent
 *   on every load.
 *
 * ## What this cannot catch
 *
 * A spoofer that patches every realm before any page script runs — a browser extension
 * content script with `all_frames` and `match_about_blank`, or a hook on the
 * `HTMLIFrameElement.prototype.contentWindow` getter that patches each new realm before
 * returning it — makes the two toStrings agree. Engine-level overrides (a patched binary,
 * CDP `Emulation.*`) change both the JS value and the CSS value of the screen consistently.
 * Deterministic DOMRect noise that preserves width = right − left per element passes the
 * rect equations (the CreepJS weakness the catalogue records for §19).
 */

import { failed, ok, probe, unavailable, type ProbeResult } from './canonical';
import { lieCodesOf } from './lies';

// ---------------------------------------------------------------------------
// The target list (shared by `lieBattery` in integrity.ts and `nativeToString` here)
// ---------------------------------------------------------------------------

/**
 * One function the lie battery and the realm toString comparison inspect.
 *
 * `get` resolves the function at CALL time, not at module load: a patch installed after this
 * module was evaluated must still be the thing that is inspected. It returns the accessor's
 * getter for an attribute and the function itself for a method; it may throw (an interface
 * that does not exist), and the callers treat a throw or a non-function as "not checked".
 */
export interface LieTarget {
    /** `Interface.member`, the name used in data and findings. Its last segment is the expected function name. */
    readonly api: string;
    readonly get: () => unknown;
}

/** `prototype` of a global interface, or undefined where the interface does not exist. */
function interfaceProto(name: string): object | undefined {
    const ctor = (globalThis as Record<string, unknown>)[name];
    if (typeof ctor !== 'function') {
        return undefined;
    }
    const proto = (ctor as { prototype?: unknown }).prototype;

    // `Function.prototype` is itself a function, so a callable prototype is accepted too.
    return (typeof proto === 'object' && proto !== null) || typeof proto === 'function' ? (proto as object) : undefined;
}

/** The getter of an accessor, or the value of a data property, read from the descriptor. */
function ownMember(owner: object | undefined, name: string): unknown {
    if (owner === undefined) {
        return undefined;
    }
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (!descriptor) {
        return undefined;
    }

    return typeof descriptor.get === 'function' ? descriptor.get : descriptor.value;
}

const onInterface = (iface: string, names: readonly string[]): LieTarget[] =>
    names.map((name) => ({ api: `${iface}.${name}`, get: () => ownMember(interfaceProto(iface), name) }));

/**
 * The fixed target list (contract §I1). Attributes are inspected through their getter,
 * methods directly. `deviceMemory`, `webdriver`, the WebGL methods, `AudioBuffer` and
 * `Permissions` are inspected only where they exist (measured: Firefox and WebKit have no
 * `deviceMemory`), so `checked` was 25 in Chromium and 24 in Firefox and WebKit before the
 * three `WebGL2RenderingContext` targets were added; the harness prints the current count.
 */
export const LIE_TARGETS: readonly LieTarget[] = Object.freeze([
    ...onInterface('Navigator', ['userAgent', 'platform', 'hardwareConcurrency', 'deviceMemory', 'languages', 'plugins', 'webdriver']),
    ...onInterface('Screen', ['width', 'height']),
    ...onInterface('HTMLCanvasElement', ['toDataURL', 'getContext', 'toBlob']),
    ...onInterface('CanvasRenderingContext2D', ['getImageData', 'fillText', 'measureText']),
    ...onInterface('WebGLRenderingContext', ['getParameter', 'getExtension', 'readPixels']),
    // WebGL 2 has its own copies of these methods (it does not inherit from WebGL 1), and
    // `sharedWebGl()` prefers WebGL 2, so a hook on WebGL 2 alone went unchecked (notes/22,
    // MEDIUM). Inspected only where the interface exists.
    ...onInterface('WebGL2RenderingContext', ['getParameter', 'getExtension', 'readPixels']),
    ...onInterface('Date', ['getTimezoneOffset']),
    { api: 'Intl.DateTimeFormat.resolvedOptions', get: () => ownMember(Intl.DateTimeFormat.prototype, 'resolvedOptions') },
    ...onInterface('AudioBuffer', ['getChannelData']),
    ...onInterface('Permissions', ['query']),
    ...onInterface('Function', ['toString']),
    { api: 'Math.sin', get: () => ownMember(Math, 'sin') },
    ...onInterface('Element', ['getBoundingClientRect']),
]);

/** Resolve a target to a function, or null when it is absent, not a function, or throws. */
export function resolveTarget(target: LieTarget): ((...args: never[]) => unknown) | null {
    try {
        const fn = target.get();
        return typeof fn === 'function' ? (fn as (...args: never[]) => unknown) : null;
    } catch {
        // An interface whose prototype getter throws is "not checked", exactly like an
        // absent one: there is no function to inspect, and absence is not evidence.
        return null;
    }
}

// ---------------------------------------------------------------------------
// phantomRealm: shapes
// ---------------------------------------------------------------------------

/** A sub-result on the wire: the raw value when it could be measured, a tagged state otherwise. */
export type SubResult<T> = T | { readonly state: 'unavailable'; readonly reason: string } | { readonly state: 'error'; readonly name: string };

/** Page toString vs fresh-realm toString, over the `LIE_TARGETS` list. */
export interface NativeToStringValue {
    readonly checked: number;
    /** `api` names whose two descriptions differ, in target-list order. Empty on a clean page. */
    readonly mismatched: readonly string[];
}

/** The three rect equations, and one device/engine geometry value. */
export interface DomRectValue {
    /** right − left = width and bottom − top = height (|Δ| < 1e-6) for every measured rect. */
    readonly math: boolean;
    /** The two identically styled, overlapping elements measure identically, field by field. */
    readonly identical: boolean;
    /** The 0×0 element at the origin measures all zeros. */
    readonly ghost: boolean;
    /** Sum of |field| over the skewed element's bounding rect, rounded to 1e-3. Data, not judged. */
    readonly sum: number;
}

export interface SvgTextValue {
    /** `getComputedTextLength()` read twice gives the same number for every string. */
    readonly repeatEqual: boolean;
    /** `getBBox().width` is within 0.5 px of `getComputedTextLength()` for every string. */
    readonly bboxAgrees: boolean;
}

/**
 * Does the CSS view of the screen agree with the JS view?
 *
 * `css*`: an `@media (min-device-width: <screen.width − 0.5>px) and (max-device-width:
 * <screen.width + 0.5>px)` rule (the same range for height, ±0.005 dppx for the resolution)
 * evaluated by the style engine in the iframe. `null` when the iframe's own calibration rule (`min-device-width: 1px`, and the
 * height and resolution equivalents) does not match, i.e. the realm has no device size to
 * compare against — see `screenTruth` for the two stock configurations where that happens.
 * `media*`: the page's `matchMedia` of the same query, which a JS-level hook can change.
 */
export interface ScreenTruthValue {
    readonly cssWidth: boolean | null;
    readonly cssHeight: boolean | null;
    readonly cssDpr: boolean | null;
    readonly mediaWidth: boolean | null;
    readonly mediaHeight: boolean | null;
    readonly mediaDpr: boolean | null;
}

/** `integrity.data.phantomRealm` when the realm could be created. */
export interface PhantomRealmValue {
    readonly nativeToString: SubResult<NativeToStringValue>;
    readonly domRect: SubResult<DomRectValue>;
    readonly svgText: SubResult<SvgTextValue>;
    readonly screenTruth: SubResult<ScreenTruthValue>;
}

/**
 * The value of a sub-result, or null when it is a tagged state.
 *
 * Sound because no value shape above has a `state` key, so a `state` key can only mean the
 * tagged form.
 */
export function subValue<T extends object>(sub: SubResult<T> | undefined): T | null {
    if (typeof sub !== 'object' || sub === null || 'state' in sub) {
        return null;
    }

    return sub;
}

const asSub = <T>(result: ProbeResult<T>): SubResult<T> => (result.state === 'ok' ? result.value : result);

/** Run a step that itself returns a tagged result; a throw becomes an `error` result. */
function attempt<T>(step: () => ProbeResult<T>): ProbeResult<T> {
    try {
        return step();
    } catch (error) {
        return failed<T>(error);
    }
}

// ---------------------------------------------------------------------------
// nativeToString
// ---------------------------------------------------------------------------

/** What `toString` says about `fn`: its text, or `throw:<ErrorName>`. Never throws. */
function describeWith(toString: unknown, fn: unknown): string {
    try {
        return String(Reflect.apply(toString as (this: unknown) => unknown, fn, []));
    } catch (error) {
        let name = 'Error';
        try {
            name = String((error as { name?: unknown }).name);
        } catch {
            // An error object whose `name` getter throws: keep the generic label.
        }
        return 'throw:' + name;
    }
}

/**
 * The page's CURRENT `Function.prototype.toString` (read at call time, so a patch installed
 * at any point before the call is what is compared) against the fresh realm's, on the same
 * page functions. Measured: identical text for all 25/24/24 targets in Chromium, Firefox and
 * WebKit, so any difference is a page-side toString patch.
 */
export function compareToString(pageToString: unknown, realmToString: unknown, targets: readonly LieTarget[] = LIE_TARGETS): NativeToStringValue {
    let checked = 0;
    const mismatched: string[] = [];

    for (const target of targets) {
        const fn = resolveTarget(target);
        if (fn === null) {
            continue;
        }
        checked++;
        if (describeWith(pageToString, fn) !== describeWith(realmToString, fn)) {
            mismatched.push(target.api);
        }
    }

    return { checked, mismatched };
}

/**
 * Whether the fresh realm's `Function.prototype.toString` can NOT serve as the pristine
 * reference: it is the page's own `toString` (planted into the realm by a capture-phase
 * `load` listener, see the file docblock), or it fails the native-function invariants
 * (`lieCodesOf`, the same eight checks as `lieBattery`). Either way, comparing against it
 * would turn a patched page into "agreement", so the comparison is reported as
 * `unavailable('realm-tampered')` instead. Never throws: a check that throws counts as tampered.
 */
export function realmToStringTampered(realmToString: unknown): boolean {
    try {
        if (typeof realmToString !== 'function') return true;
        if (realmToString === Function.prototype.toString) return true;
        return lieCodesOf(realmToString as (...args: never[]) => unknown, 'toString').length > 0;
    } catch {
        return true;
    }
}

// ---------------------------------------------------------------------------
// domRect
// ---------------------------------------------------------------------------

/** x, y, width, height, top, right, bottom, left. */
export type RectFields = readonly number[];

/** One element measured both ways. `client` is null when `getClientRects()` is empty. */
export interface RectPair {
    readonly box: RectFields;
    readonly client: RectFields | null;
}

export interface DomRectSamples {
    readonly skewed: RectPair;
    readonly twinA: RectPair;
    readonly twinB: RectPair;
    readonly ghost: RectPair;
}

const RECT_TOLERANCE = 1e-6;

/**
 * The four elements. Fractional borders, margins, paddings and offsets, and a perspective /
 * rotate3d / skew transform, so every field is a non-trivial float (CreepJS §19's idea; the
 * values are this file's own). The twins are byte-identical and absolutely positioned at the
 * SAME place, so all eight fields must be equal — not just left/right as in CreepJS, whose
 * twins are stacked and can only share the horizontal fields. The ghost is a 0×0 box at the
 * iframe's origin. Borders name no colour (it defaults to `currentColor`): colour has no
 * effect on geometry, and a literal colour here would trip the token ratchet
 * (tokenColours.spec.ts) for a box nobody sees.
 */
const RECT_STYLE = {
    skewed:
        'position:absolute;box-sizing:content-box;left:10.3px;top:20.7px;width:101.13px;height:50.71px;' +
        'border:2.31px solid;margin:1.17px;padding:3.59px;' +
        'transform:perspective(812.3px) rotate3d(1.7,2.3,0.7,23.17deg) skewX(3.31deg)',
    twin:
        'position:absolute;box-sizing:content-box;left:30.37px;top:120.53px;width:77.77px;height:33.33px;' +
        'border:2.31px solid;margin:1.17px;padding:3.59px;' +
        'transform:rotate3d(2,1,3,41.3deg) scale(1.0371)',
    ghost: 'position:absolute;left:0;top:0;width:0;height:0;margin:0;padding:0;border:0',
} as const;

const rectFields = (r: DOMRectReadOnly): RectFields => [r.x, r.y, r.width, r.height, r.top, r.right, r.bottom, r.left];

function measurePair(element: Element): RectPair {
    const first = element.getClientRects()[0];

    return { box: rectFields(element.getBoundingClientRect()), client: first ? rectFields(first) : null };
}

const fieldsConsistent = (f: RectFields): boolean => {
    const [, , width, height, top, right, bottom, left] = f as [number, number, number, number, number, number, number, number];

    // No separate finiteness test: a NaN or infinite field makes one of the two differences
    // NaN or infinite, and neither is < the tolerance.
    return Math.abs(right - left - width) < RECT_TOLERANCE && Math.abs(bottom - top - height) < RECT_TOLERANCE;
};

const fieldsEqual = (a: RectFields | null, b: RectFields | null): boolean =>
    a === null || b === null ? a === b : a.length === b.length && a.every((value, i) => value === b[i]);

const allZero = (f: RectFields | null): boolean => f === null || (f.length === 8 && f.every((value) => value === 0));

/**
 * The three DOMRect equations over measured samples. Pure, so the arithmetic is tested on
 * fakes; that a stock engine satisfies it is asserted by the real-browser harness.
 *
 * Measured in Chromium, Firefox and WebKit: every Δ is exactly 0, the twins are bit-identical
 * and the ghost is all zeros, so the 1e-6 tolerance only absorbs float subtraction, never a
 * real difference.
 */
export function evaluateDomRect(samples: DomRectSamples): DomRectValue {
    const pairs = [samples.skewed, samples.twinA, samples.twinB, samples.ghost];
    const math = pairs.every((pair) => fieldsConsistent(pair.box) && (pair.client === null || fieldsConsistent(pair.client)));
    const identical = fieldsEqual(samples.twinA.box, samples.twinB.box) && fieldsEqual(samples.twinA.client, samples.twinB.client);
    const ghost = allZero(samples.ghost.box) && allZero(samples.ghost.client);
    const sum = samples.skewed.box.reduce((total, value) => total + Math.abs(value), 0);

    return { math, identical, ghost, sum: Math.round(sum * 1000) / 1000 };
}

// ---------------------------------------------------------------------------
// svgText
// ---------------------------------------------------------------------------

/** One `<text>` element: two `getComputedTextLength()` reads and the bbox width. */
export interface SvgTextSample {
    readonly first: number;
    readonly second: number;
    readonly bboxWidth: number;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * ASCII only, deliberately. A first version also measured a Latin-1 string (`ÆØÅ ſßÿ`), and
 * Chromium's bbox exceeded its computed text length by 0.357 px on it — inside the 0.5 px
 * tolerance, but too close for a check that must never fire on a stock engine with other
 * fonts. On these three strings the measured difference is 0 in Chromium and Firefox and at
 * most 1/64 px in WebKit (which snaps the bbox to its 1/64 px layout unit).
 */
const SVG_STRINGS = ['Hamburgefonstiv 0123', 'Quixotic jabs vow 7.5%', 'Sphinx of black quartz'] as const;

const SVG_BBOX_TOLERANCE_PX = 0.5;

/** The two SVG text equations over measured samples. Pure, for the same reason as `evaluateDomRect`. */
export function evaluateSvgText(samples: readonly SvgTextSample[]): SvgTextValue {
    return {
        repeatEqual: samples.every((s) => Number.isFinite(s.first) && s.first === s.second),
        bboxAgrees: samples.every((s) => Number.isFinite(s.bboxWidth) && Math.abs(s.bboxWidth - s.first) <= SVG_BBOX_TOLERANCE_PX),
    };
}

// ---------------------------------------------------------------------------
// The realm
// ---------------------------------------------------------------------------

/** The iframe's inline style, written through the CSSOM. Contract §I2. */
export const PHANTOM_IFRAME_STYLE = 'position:absolute;left:-9999px;width:0;height:0;visibility:hidden';

type Realm = Window & typeof globalThis;

/** A step that has built its elements and will read them later, after every step has built. */
type Reader<T> = () => ProbeResult<T>;

function staged<T>(build: () => Reader<T>): Reader<T> {
    let reader: Reader<T>;
    try {
        reader = build();
    } catch (error) {
        const result = failed<T>(error);
        return () => result;
    }

    return () => attempt(reader);
}

function element(doc: Document, host: Element, css: string): HTMLElement {
    const el = doc.createElement('div');
    el.style.cssText = css;
    host.appendChild(el);

    return el;
}

function buildDomRect(doc: Document, host: Element): Reader<DomRectValue> {
    const skewed = element(doc, host, RECT_STYLE.skewed);
    const twinA = element(doc, host, RECT_STYLE.twin);
    const twinB = element(doc, host, RECT_STYLE.twin);
    const ghost = element(doc, host, RECT_STYLE.ghost);

    return () =>
        ok(
            evaluateDomRect({
                skewed: measurePair(skewed),
                twinA: measurePair(twinA),
                twinB: measurePair(twinB),
                ghost: measurePair(ghost),
            }),
        );
}

function buildSvgText(doc: Document, host: Element): Reader<SvgTextValue> {
    const svg = doc.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('width', '600');
    svg.setAttribute('height', '160');
    const texts = SVG_STRINGS.map((content, i) => {
        const text = doc.createElementNS(SVG_NS, 'text') as SVGTextElement;
        text.setAttribute('x', '4');
        text.setAttribute('y', String(30 + i * 40));
        text.setAttribute('font-size', '17.3');
        text.textContent = content;
        svg.appendChild(text);
        return text;
    });
    host.appendChild(svg);

    return () => {
        const sample = texts[0] as unknown as Partial<SVGTextElement>;
        if (typeof sample.getComputedTextLength !== 'function' || typeof sample.getBBox !== 'function') {
            return unavailable('no-svg-text');
        }

        return ok(
            evaluateSvgText(
                texts.map((text) => {
                    const first = text.getComputedTextLength();
                    const second = text.getComputedTextLength();
                    return { first, second, bboxWidth: text.getBBox().width };
                }),
            ),
        );
    };
}

/** The custom properties the screen rules set on `<html>` when they match. */
const SCREEN_PROPS = { width: '--nc-w', height: '--nc-h', dpr: '--nc-d', calWidth: '--nc-cw', calHeight: '--nc-ch', calDpr: '--nc-cd' } as const;

/**
 * Item 9: the CSS truth about the screen.
 *
 * The rules are inserted through a CONSTRUCTED stylesheet adopted by the iframe document
 * (CSSOM, not a `<style>` element: see the file docblock on CSP). Each dimension also gets a
 * calibration rule that matches any real device (`min-device-width: 1px`, and so on). The
 * calibration exists because of two measurements:
 *
 * - Playwright's WebKit (Linux, headless) evaluates `device-width` and `device-height` as 0
 *   inside ANY subframe (0×0 hidden, 1×1, 10×10 visible, on-screen — all tried; the
 *   subframe's own `screen.width` is 0 too), while the page's `matchMedia` matches. Without
 *   calibration `cssWidth` and `cssHeight` would both be false on a stock engine.
 * - Firefox with `privacy.resistFingerprinting` evaluates `device-width` as the FRAME's
 *   viewport, i.e. 0 in a 0×0 iframe.
 *
 * In both cases the calibration rule does not match and the field is `null` ("could not
 * measure"), not `false`. A JS-level spoof of `screen.width` on a real device leaves the
 * calibration matching and the comparison false, which is the case the server rule
 * `screen_vs_css_media` exists for. Whether real Safari has the WebKit behaviour is
 * UNVERIFIED (no macOS/iOS engine here); if it does, the field is null there too.
 *
 * NO finding here: DPR with page zoom and Gecko's fractional dimensions are honest mismatch
 * sources, and the server rule decides.
 */
function buildScreenTruth(realm: Realm, doc: Document): Reader<ScreenTruthValue> {
    const width = screen.width;
    const height = screen.height;
    const dpr = devicePixelRatio;
    const finite = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n);

    // RANGES, not equalities: Gecko reports integer `screen.*` but evaluates a FRACTIONAL
    // `device-width`/`device-height` at 125 % / 175 % OS scaling (verified by two reviewers with
    // `layout.css.devPixelsPerPx=1.25`), so `(device-width: 1536px)` missed on both axes on an
    // honest Firefox and fed a 20-weight server rule. Half a CSS pixel either side, and
    // ±0.005 dppx for the resolution, absorb that rounding and nothing a spoofer changes.
    const around = (value: number, delta: number): [string, string] => [
        String(Number((value - delta).toFixed(6))),
        String(Number((value + delta).toFixed(6))),
    ];
    const range = (feature: string, value: number, delta: number, unit: string): string => {
        const [low, high] = around(value, delta);
        return `(min-${feature}: ${low}${unit}) and (max-${feature}: ${high}${unit})`;
    };
    const queries = {
        width: finite(width) ? range('device-width', width, 0.5, 'px') : null,
        height: finite(height) ? range('device-height', height, 0.5, 'px') : null,
        dpr: finite(dpr) ? range('resolution', dpr, 0.005, 'dppx') : null,
    };

    // The custom properties whose rule really was inserted and adopted. A rule that was not
    // (no constructable stylesheets, or an engine that rejects one rule) makes its field
    // null rather than false: an absent rule is "not measured", never "did not match".
    const installed = new Set<string>();
    const Sheet = (realm as { CSSStyleSheet?: unknown }).CSSStyleSheet;
    const adoptable = doc as Document & { adoptedStyleSheets?: CSSStyleSheet[] };
    if (typeof Sheet === 'function' && Array.isArray(adoptable.adoptedStyleSheets)) {
        const sheet = new (Sheet as typeof CSSStyleSheet)();
        const rules: Array<[string | null, string]> = [
            [queries.width, SCREEN_PROPS.width],
            [queries.height, SCREEN_PROPS.height],
            [queries.dpr, SCREEN_PROPS.dpr],
            ['(min-device-width: 1px)', SCREEN_PROPS.calWidth],
            ['(min-device-height: 1px)', SCREEN_PROPS.calHeight],
            ['(min-resolution: 0.01dppx)', SCREEN_PROPS.calDpr],
        ];
        const inserted: string[] = [];
        for (const [query, prop] of rules) {
            if (query === null) continue;
            try {
                sheet.insertRule(`@media ${query}{html{${prop}:1}}`, sheet.cssRules.length);
                inserted.push(prop);
            } catch {
                // A rule the engine rejects leaves its property out of `installed`, which
                // reports the field as null ("not measured") — the intended outcome.
            }
        }
        adoptable.adoptedStyleSheets = [...adoptable.adoptedStyleSheets, sheet];
        for (const prop of inserted) installed.add(prop);
    }

    const pageMatch = (query: string | null): boolean | null =>
        query !== null && typeof matchMedia === 'function' ? matchMedia(query).matches : null;

    return () => {
        const computed = installed.size > 0 ? realm.getComputedStyle(doc.documentElement) : null;
        const set = (prop: string): boolean => computed !== null && computed.getPropertyValue(prop).trim() === '1';
        const css = (query: string | null, prop: string, calibration: string): boolean | null =>
            query === null || !installed.has(prop) || !installed.has(calibration) || !set(calibration) ? null : set(prop);

        return ok({
            cssWidth: css(queries.width, SCREEN_PROPS.width, SCREEN_PROPS.calWidth),
            cssHeight: css(queries.height, SCREEN_PROPS.height, SCREEN_PROPS.calHeight),
            cssDpr: css(queries.dpr, SCREEN_PROPS.dpr, SCREEN_PROPS.calDpr),
            mediaWidth: pageMatch(queries.width),
            mediaHeight: pageMatch(queries.height),
            mediaDpr: pageMatch(queries.dpr),
        });
    };
}

/** Everything that runs while the iframe is attached. Build every step first, then read: one style/layout pass. */
function inRealm(realm: Realm, doc: Document, targets: readonly LieTarget[]): PhantomRealmValue {
    const nativeToString = attempt((): ProbeResult<NativeToStringValue> => {
        const realmToString = realm.Function.prototype.toString;
        return realmToStringTampered(realmToString)
            ? unavailable('realm-tampered')
            : ok(compareToString(Function.prototype.toString, realmToString, targets));
    });

    const host = doc.body ?? doc.documentElement;
    const domRect = staged(() => buildDomRect(doc, host));
    const svgText = staged(() => buildSvgText(doc, host));
    const screenTruth = staged(() => buildScreenTruth(realm, doc));

    return {
        nativeToString: asSub(nativeToString),
        domRect: asSub(domRect()),
        svgText: asSub(svgText()),
        screenTruth: asSub(screenTruth()),
    };
}

/** Internal marker: no realm could be created. Never on the wire. */
const NO_REALM = Symbol('no-realm');

/**
 * Detach the iframe. Called from a `finally`, so it must not throw; removing a node this
 * function itself appended a moment ago cannot fail in a conformant DOM, and if a page
 * patch makes it fail there is nothing better to do than leave the remove to `remove()`.
 */
function detach(iframe: HTMLIFrameElement): void {
    try {
        iframe.parentNode?.removeChild(iframe);
    } catch {
        try {
            iframe.remove();
        } catch {
            // Both removal paths threw: only a page that patched Node.prototype can do
            // that, and throwing from a finally would abort the whole collection.
        }
    }
}

/**
 * Probe — the phantom realm (contract §I2). See the file docblock.
 *
 * `unavailable('no-document')` without a DOM, `unavailable('no-realm')` when the iframe has
 * no `contentWindow` or `contentDocument` (a page or extension that blocks frames). Each
 * sub-result is measured independently: one that cannot be measured is a tagged state inside
 * the value and the others are still reported.
 */
export function phantomRealm(targets: readonly LieTarget[] = LIE_TARGETS): ProbeResult<PhantomRealmValue> {
    const measured = probe('phantomRealm', (): PhantomRealmValue | typeof NO_REALM | null => {
        if (typeof document === 'undefined' || !document.documentElement) {
            return null;
        }

        const iframe = document.createElement('iframe');
        iframe.setAttribute('aria-hidden', 'true');
        iframe.tabIndex = -1;
        iframe.style.cssText = PHANTOM_IFRAME_STYLE;

        try {
            document.documentElement.appendChild(iframe);
            const realm = iframe.contentWindow as Realm | null;
            const doc = iframe.contentDocument;
            if (!realm || !doc) {
                return NO_REALM;
            }

            return inRealm(realm, doc, targets);
        } finally {
            detach(iframe);
        }
    });

    if (measured.state !== 'ok') return measured;
    if (measured.value === null) return unavailable('no-document');
    if (measured.value === NO_REALM) return unavailable('no-realm');

    return ok(measured.value);
}

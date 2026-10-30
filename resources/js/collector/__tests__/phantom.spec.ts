/**
 * `phantomRealm` (phantom.ts) and the three findings it feeds: `realm_tostring_mismatch`,
 * `domrect_inconsistent`, `svg_text_inconsistent`. All three are raised by the DEFERRED
 * integrity phase (`collectDeferredIntegrity`), which is where `phantomRealm` runs.
 *
 * jsdom has a real second realm for an `about:blank` iframe (its own `Function`, `Element`,
 * `getComputedStyle`), but no layout: every rect is zero and SVG text has no metrics. So:
 *
 * - the rect and SVG ARITHMETIC is tested on fakes: directly through the pure evaluators, and
 *   end to end by installing a fake `getBoundingClientRect` / `getComputedTextLength` in the
 *   iframe's realm the moment the probe asks for the iframe's document (a hook on the page's
 *   `HTMLIFrameElement.prototype.contentDocument`, the same path a realm-patching extension
 *   would take);
 * - each finding is shown to FIRE on a perturbed fake and to stay SILENT on a conformant one;
 * - that a stock Chromium, Firefox and WebKit produce none of them, and that their values are
 *   identical across loads, is asserted against the real engines in
 *   tests/Browser/transport-checks.mjs.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { collectDeferredIntegrity, collectIntegrity, INTEGRITY_CODES, phantomFindings } from '@device-id/collector/integrity';
import {
    compareToString,
    evaluateDomRect,
    evaluateSvgText,
    LIE_TARGETS,
    phantomRealm,
    PHANTOM_IFRAME_STYLE,
    realmToStringTampered,
    subValue,
    type DomRectSamples,
    type LieTarget,
    type PhantomRealmValue,
    type RectPair,
} from '@device-id/collector/phantom';

const undos: Array<() => void> = [];
afterEach(() => {
    vi.restoreAllMocks();
    while (undos.length) undos.pop()?.();
});

function defineOwn(target: object, name: string, descriptor: PropertyDescriptor): void {
    const original = Object.getOwnPropertyDescriptor(target, name);
    Object.defineProperty(target, name, { configurable: true, ...descriptor });
    undos.push(() => {
        if (original) Object.defineProperty(target, name, original);
        else delete (target as Record<string, unknown>)[name];
    });
}

type Realm = Window & typeof globalThis;

/** Run `install` against the iframe's realm when the probe first asks for its document. */
function onRealm(install: (realm: Realm, doc: Document) => void): void {
    const original = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentDocument');
    expect(original?.get).toBeTypeOf('function');
    defineOwn(HTMLIFrameElement.prototype, 'contentDocument', {
        get(this: HTMLIFrameElement) {
            const doc = original?.get?.call(this) as Document | null;
            if (doc?.defaultView) install(doc.defaultView as Realm, doc);
            return doc;
        },
    });
}

const codes = (): string[] => collectDeferredIntegrity().findings.map((f) => f.code);
const phantomOf = (report: ReturnType<typeof collectDeferredIntegrity>): PhantomRealmValue | null =>
    report.data.phantomRealm?.state === 'ok' ? (report.data.phantomRealm.value as PhantomRealmValue) : null;
/** Which domRect equations held, and which svgText checks: the data the server reads, since findings carry codes only. */
const domRectOf = (report: ReturnType<typeof collectDeferredIntegrity>) => subValue(phantomOf(report)?.domRect);
const svgTextOf = (report: ReturnType<typeof collectDeferredIntegrity>) => subValue(phantomOf(report)?.svgText);
const iframesLeft = (): number => document.querySelectorAll('iframe').length;

function realmValue(): PhantomRealmValue {
    const result = phantomRealm();
    expect(result.state).toBe('ok');
    if (result.state !== 'ok') throw new Error('phantomRealm was not ok');
    return result.value;
}

// ---------------------------------------------------------------------------
// Pure evaluators
// ---------------------------------------------------------------------------

/** A consistent rect: x, y, width, height, top, right, bottom, left. */
const rect = (x: number, y: number, w: number, h: number): number[] => [x, y, w, h, y, x + w, y + h, x];
const pair = (fields: number[], client: number[] | null = fields): RectPair => ({ box: fields, client });

const CONFORMANT: DomRectSamples = {
    skewed: pair(rect(12.805269241333008, 14.838747024536133, 107.21060943603516, 74.97651672363281)),
    twinA: pair(rect(26.671405792236328, 100.13540649414062, 98.61030578613281, 87.55731201171875)),
    twinB: pair(rect(26.671405792236328, 100.13540649414062, 98.61030578613281, 87.55731201171875)),
    ghost: pair(rect(0, 0, 0, 0)),
};

describe('evaluateDomRect', () => {
    it('passes a conformant set (the Chromium-measured skewed and twin rects) and sums the skewed box', () => {
        const skewed = CONFORMANT.skewed.box;
        const expectedSum = Math.round(skewed.reduce((t, v) => t + Math.abs(v), 0) * 1000) / 1000;

        expect(evaluateDomRect(CONFORMANT)).toEqual({ math: true, identical: true, ghost: true, sum: expectedSum });
        // The value the harness measured in Chromium for this geometry.
        expect(expectedSum).toBe(447.306);
    });

    it('fails math when right - left is not width, on the bounding box or on the client rect', () => {
        const box = [...CONFORMANT.skewed.box];
        box[5] = (box[5] as number) + 0.01;
        expect(evaluateDomRect({ ...CONFORMANT, skewed: pair(box) }).math).toBe(false);

        const client = [...CONFORMANT.twinA.box];
        client[6] = (client[6] as number) - 0.001;
        expect(evaluateDomRect({ ...CONFORMANT, twinA: pair(CONFORMANT.twinA.box, client), twinB: pair(CONFORMANT.twinA.box, client) }).math).toBe(false);
    });

    it('tolerates float subtraction error below 1e-6, and nothing more', () => {
        const box = [...CONFORMANT.skewed.box];
        box[5] = (box[5] as number) + 5e-7;
        expect(evaluateDomRect({ ...CONFORMANT, skewed: pair(box) }).math).toBe(true);
        box[5] = (box[5] as number) + 1e-6;
        expect(evaluateDomRect({ ...CONFORMANT, skewed: pair(box) }).math).toBe(false);
    });

    it.each([
        ['NaN width', 2, Number.NaN],
        ['infinite right', 5, Number.POSITIVE_INFINITY],
        ['infinite top', 4, Number.NEGATIVE_INFINITY],
    ])('fails math on a non-finite field (%s)', (_label, index, value) => {
        const box = [...CONFORMANT.skewed.box];
        box[index] = value;
        expect(evaluateDomRect({ ...CONFORMANT, skewed: pair(box) }).math).toBe(false);
    });

    it('fails identical when the twins differ in any field, even consistently (per-call noise)', () => {
        const shifted = rect(26.671405792236328 + 1e-9, 100.13540649414062, 98.61030578613281, 87.55731201171875);
        const result = evaluateDomRect({ ...CONFORMANT, twinB: pair(shifted) });

        expect(result.math).toBe(true);
        expect(result.identical).toBe(false);
    });

    it('fails identical when only one twin has a client rect', () => {
        expect(evaluateDomRect({ ...CONFORMANT, twinB: pair(CONFORMANT.twinA.box, null) }).identical).toBe(false);
    });

    it('fails ghost on the bounding box alone, with no client rect to give it away', () => {
        const result = evaluateDomRect({ ...CONFORMANT, ghost: pair(rect(0, 0.25, 0, 0), null) });

        expect(result.ghost).toBe(false);
    });

    it('fails ghost when the 0x0 element measures anything but zeros', () => {
        const result = evaluateDomRect({ ...CONFORMANT, ghost: pair(rect(0.0001, 0, 0, 0)) });

        expect(result.math).toBe(true);
        expect(result.ghost).toBe(false);
    });

    it('accepts elements with no client rect (an unrendered document)', () => {
        const none: DomRectSamples = {
            skewed: pair(rect(0, 0, 0, 0), null),
            twinA: pair(rect(0, 0, 0, 0), null),
            twinB: pair(rect(0, 0, 0, 0), null),
            ghost: pair(rect(0, 0, 0, 0), null),
        };
        expect(evaluateDomRect(none)).toEqual({ math: true, identical: true, ghost: true, sum: 0 });
    });
});

describe('evaluateSvgText', () => {
    const honest = [
        { first: 159.515625, second: 159.515625, bboxWidth: 159.515625 },
        { first: 198.812744140625, second: 198.812744140625, bboxWidth: 198.828125 }, // WebKit's 1/64 px snap
    ];

    it('passes repeatable lengths whose bbox agrees within 0.5 px', () => {
        expect(evaluateSvgText(honest)).toEqual({ repeatEqual: true, bboxAgrees: true });
    });

    it('fails repeatEqual when two reads of the same text differ', () => {
        expect(evaluateSvgText([...honest, { first: 100, second: 100.000001, bboxWidth: 100 }]).repeatEqual).toBe(false);
    });

    it('fails bboxAgrees beyond 0.5 px, and passes at exactly 0.5 px', () => {
        expect(evaluateSvgText([{ first: 100, second: 100, bboxWidth: 100.5 }]).bboxAgrees).toBe(true);
        expect(evaluateSvgText([{ first: 100, second: 100, bboxWidth: 100.51 }]).bboxAgrees).toBe(false);
        expect(evaluateSvgText([{ first: 100, second: 100, bboxWidth: 99.4 }]).bboxAgrees).toBe(false);
    });

    it('fails both on non-finite measurements', () => {
        expect(evaluateSvgText([{ first: Number.NaN, second: Number.NaN, bboxWidth: Number.NaN }])).toEqual({ repeatEqual: false, bboxAgrees: false });
    });
});

describe('compareToString', () => {
    const targets: LieTarget[] = [
        { api: 'Math.sin', get: () => Math.sin },
        { api: 'Fake.width', get: () => fakeGetter },
        { api: 'Gone.member', get: () => undefined },
    ];
    const fakeGetter = (): number => 1920;
    const pristine = Function.prototype.toString;

    it('reports nothing when both realms describe every function identically', () => {
        expect(compareToString(pristine, pristine, targets)).toEqual({ checked: 2, mismatched: [] });
    });

    it('names the api whose page-side description is a lie', () => {
        const lying = function toString(this: unknown): string {
            return this === fakeGetter ? 'function get width() { [native code] }' : pristine.call(this);
        };

        expect(compareToString(lying, pristine, targets)).toEqual({ checked: 2, mismatched: ['Fake.width'] });
    });

    it('counts a page toString that throws as a mismatch, without throwing', () => {
        const throwing = (): string => {
            throw new TypeError('blocked');
        };

        expect(compareToString(throwing, pristine, targets)).toEqual({ checked: 2, mismatched: ['Math.sin', 'Fake.width'] });
    });
});

describe('subValue', () => {
    it('unwraps a raw value and rejects a tagged state', () => {
        expect(subValue({ math: true })).toEqual({ math: true });
        expect(subValue({ state: 'unavailable', reason: 'no-svg-text' })).toBeNull();
        expect(subValue({ state: 'error', name: 'TypeError' })).toBeNull();
        expect(subValue(undefined)).toBeNull();
    });
});

// ---------------------------------------------------------------------------
// The realm itself (jsdom)
// ---------------------------------------------------------------------------

describe('phantomRealm', () => {
    it('reports no cssSystem sub-result (removed: nothing consumed it)', () => {
        expect(Object.keys(realmValue()).sort()).toEqual(['domRect', 'nativeToString', 'screenTruth', 'svgText']);
    });

    it('measures in a real second realm and leaves no iframe behind', () => {
        const before = iframesLeft();
        const value = realmValue();

        expect(iframesLeft()).toBe(before);
        expect(value.nativeToString).toEqual({ checked: expect.any(Number), mismatched: [] });
        expect(subValue(value.nativeToString)?.checked).toBeGreaterThan(5);
        // jsdom has no layout: every rect is zero, which satisfies all three equations.
        expect(value.domRect).toEqual({ math: true, identical: true, ghost: true, sum: 0 });
        // ...and no SVG text metrics: unavailable, never a finding.
        expect(value.svgText).toEqual({ state: 'unavailable', reason: 'no-svg-text' });
        expect(phantomFindings(value)).toEqual([]);
    });

    it('creates the iframe on documentElement, hidden, aria-hidden and out of the tab order', () => {
        const seen: Array<Record<string, unknown>> = [];
        const original = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        defineOwn(HTMLIFrameElement.prototype, 'contentWindow', {
            get(this: HTMLIFrameElement) {
                seen.push({
                    parent: this.parentNode,
                    ariaHidden: this.getAttribute('aria-hidden'),
                    tabIndex: this.tabIndex,
                    style: this.style.cssText,
                });
                return original?.get?.call(this);
            },
        });

        realmValue();

        // jsdom's own contentDocument getter reads contentWindow too, so it may be seen twice.
        expect(seen.length).toBeGreaterThanOrEqual(1);
        expect(seen[0]?.parent).toBe(document.documentElement);
        expect(seen[0]?.ariaHidden).toBe('true');
        expect(seen[0]?.tabIndex).toBe(-1);
        const probeStyle = document.createElement('div');
        probeStyle.style.cssText = PHANTOM_IFRAME_STYLE;
        expect(seen[0]?.style).toBe(probeStyle.style.cssText);
    });

    it('is unavailable("no-realm") when the frame has no window, and still removes it', () => {
        defineOwn(HTMLIFrameElement.prototype, 'contentWindow', { get: () => null });

        expect(phantomRealm()).toEqual({ state: 'unavailable', reason: 'no-realm' });
        expect(iframesLeft()).toBe(0);
        expect(codes()).not.toContain(INTEGRITY_CODES.REALM_TOSTRING_MISMATCH);
    });

    it('is an error, not a throw and not a finding, when the realm throws — and the iframe is still removed', () => {
        defineOwn(HTMLIFrameElement.prototype, 'contentDocument', {
            get: () => {
                throw new DOMException('blocked', 'SecurityError');
            },
        });

        expect(phantomRealm()).toEqual({ state: 'error', name: 'Error' });
        expect(iframesLeft()).toBe(0);
    });

    it('keeps the other sub-results when one sub-probe throws', () => {
        onRealm((realm, doc) => {
            (doc as Document & { adoptedStyleSheets?: CSSStyleSheet[] }).adoptedStyleSheets = [];
            realm.getComputedStyle = (() => {
                throw new TypeError('blocked');
            }) as typeof realm.getComputedStyle;
        });

        const value = realmValue();
        expect(value.screenTruth).toEqual({ state: 'error', name: 'TypeError' });
        expect(value.domRect).toEqual({ math: true, identical: true, ghost: true, sum: 0 });
        expect(subValue(value.nativeToString)?.mismatched).toEqual([]);
    });
});

// ---------------------------------------------------------------------------
// realm_tostring_mismatch, end to end
// ---------------------------------------------------------------------------

describe('realm_tostring_mismatch', () => {
    it('FIRES when the page toString hides a patched getter, which the lie battery alone cannot see', () => {
        const original = Object.getOwnPropertyDescriptor(Screen.prototype, 'width');
        const fake = (): number => 1920;
        defineOwn(Screen.prototype, 'width', { get: fake });

        const pristine = Function.prototype.toString;
        const lying = function toString(this: unknown): string {
            return this === fake ? 'function get width() { [native code] }' : pristine.call(this);
        };

        let report: ReturnType<typeof collectDeferredIntegrity>;
        let syncReport: ReturnType<typeof collectIntegrity>;
        Function.prototype.toString = lying;
        try {
            report = collectDeferredIntegrity();
            syncReport = collectIntegrity();
        } finally {
            Function.prototype.toString = pristine;
        }

        const mismatch = report.findings.filter((f) => f.code === INTEGRITY_CODES.REALM_TOSTRING_MISMATCH);
        expect(mismatch).toEqual([{ code: INTEGRITY_CODES.REALM_TOSTRING_MISMATCH }]);
        const realm = report.data.phantomRealm?.state === 'ok' ? (report.data.phantomRealm.value as PhantomRealmValue) : null;
        expect(subValue(realm?.nativeToString)?.mismatched).toEqual(['Screen.width']);
        // The lie battery's own to_string check (sync phase) was fooled by the same patch.
        const battery = syncReport.data.lieBattery;
        expect(battery?.state === 'ok' && (battery.value as { lied: Record<string, string> }).lied['Screen.width']).toBeUndefined();
        expect(original?.get).toBeTypeOf('function');
    });

    it('is silent on a patched getter whose page toString is honest (the lie battery data has it instead)', () => {
        defineOwn(Screen.prototype, 'width', { get: () => 1920 });

        expect(codes()).not.toContain(INTEGRITY_CODES.REALM_TOSTRING_MISMATCH);
    });
});

describe('realm-tampered', () => {
    it('is unavailable, never agreement, when the realm\'s toString IS the page\'s (planted by a load listener)', () => {
        // What a capture-phase `load` listener can do while the iframe is attached: hand the
        // new realm the page's (patched) toString, so the two would trivially "agree".
        const fake = (): number => 1920;
        defineOwn(Screen.prototype, 'width', { get: fake });
        const pristine = Function.prototype.toString;
        const lying = function toString(this: unknown): string {
            return this === fake ? 'function get width() { [native code] }' : pristine.call(this);
        };
        onRealm((realm) => {
            realm.Function.prototype.toString = Function.prototype.toString;
        });

        let value: PhantomRealmValue;
        let report: ReturnType<typeof collectDeferredIntegrity>;
        Function.prototype.toString = lying;
        try {
            value = realmValue();
            report = collectDeferredIntegrity();
        } finally {
            Function.prototype.toString = pristine;
        }

        expect(value.nativeToString).toEqual({ state: 'unavailable', reason: 'realm-tampered' });
        expect(report.findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.REALM_TOSTRING_MISMATCH);
        // The other sub-results are still measured.
        expect(value.domRect).toEqual({ math: true, identical: true, ghost: true, sum: 0 });
    });

    it('is unavailable when the realm\'s toString is replaced by a closure that fails the native invariants', () => {
        onRealm((realm) => {
            realm.Function.prototype.toString = function toString(this: unknown): string {
                return 'function () { [native code] }';
            };
        });

        expect(realmValue().nativeToString).toEqual({ state: 'unavailable', reason: 'realm-tampered' });
    });

    it('realmToStringTampered: false for a fresh realm\'s native toString, true for the page\'s, a closure or a non-function', () => {
        const iframe = document.createElement('iframe');
        document.documentElement.appendChild(iframe);
        try {
            const realm = iframe.contentWindow as Realm;
            expect(realmToStringTampered(realm.Function.prototype.toString)).toBe(false);
        } finally {
            iframe.remove();
        }
        expect(realmToStringTampered(Function.prototype.toString)).toBe(true);
        expect(realmToStringTampered(function toString(): string { return ''; })).toBe(true);
        expect(realmToStringTampered(undefined)).toBe(true);
        expect(realmToStringTampered(new Proxy(Function.prototype.toString, {}))).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// domrect_inconsistent, end to end
// ---------------------------------------------------------------------------

type RectNoise = (el: HTMLElement, base: number[], call: number) => number[];

/**
 * A layout fake for the iframe realm: each element's rect is its own inline left/top/width/
 * height, so the twins coincide and the ghost is zero — a conformant engine — until `noise`
 * perturbs it.
 */
function fakeLayout(noise: RectNoise = (_el, base) => base): void {
    onRealm((realm) => {
        let call = 0;
        const measure = (el: HTMLElement): DOMRectReadOnly => {
            const px = (v: string): number => Number.parseFloat(v) || 0;
            const base = rect(px(el.style.left), px(el.style.top), px(el.style.width), px(el.style.height));
            const [x, y, width, height, top, right, bottom, left] = noise(el, base, call++) as [number, number, number, number, number, number, number, number];
            return { x, y, width, height, top, right, bottom, left, toJSON: () => ({}) };
        };
        realm.Element.prototype.getBoundingClientRect = function (this: HTMLElement) {
            return measure(this);
        };
        realm.Element.prototype.getClientRects = function (this: HTMLElement) {
            return [measure(this)] as unknown as DOMRectList;
        };
    });
}

describe('domrect_inconsistent', () => {
    it('is silent on a conformant layout, and reports the skewed element’s sum as data', () => {
        fakeLayout();

        const report = collectDeferredIntegrity();
        expect(report.findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.DOMRECT_INCONSISTENT);
        const value = report.data.phantomRealm?.state === 'ok' ? (report.data.phantomRealm.value as PhantomRealmValue) : null;
        // 10.3 + 20.7 + 101.13 + 50.71 + 20.7 + 111.43 + 71.41 + 10.3
        expect(subValue(value?.domRect)).toEqual({ math: true, identical: true, ghost: true, sum: 396.68 });
    });

    it('FIRES on per-field noise (right no longer left + width)', () => {
        fakeLayout((_el, base) => base.map((v, i) => (i === 5 ? v + 0.003 : v)));

        const report = collectDeferredIntegrity();
        expect(report.findings.find((f) => f.code === INTEGRITY_CODES.DOMRECT_INCONSISTENT)).toEqual({ code: INTEGRITY_CODES.DOMRECT_INCONSISTENT });
        expect(domRectOf(report)).toMatchObject({ math: false, identical: true });
    });

    it('FIRES on per-call noise that keeps each rect consistent but makes the twins differ', () => {
        fakeLayout((_el, base, call) => {
            const [x, y, w, h] = base as [number, number, number, number];
            if (w === 0) return base; // the ghost stays honest: only the twins are under test
            const shift = call * 1e-4;
            return rect(x + shift, y, w, h);
        });

        const report = collectDeferredIntegrity();
        expect(report.findings.find((f) => f.code === INTEGRITY_CODES.DOMRECT_INCONSISTENT)).toEqual({ code: INTEGRITY_CODES.DOMRECT_INCONSISTENT });
        expect(domRectOf(report)).toMatchObject({ math: true, identical: false, ghost: true });
    });

    it('FIRES when the 0x0 element measures non-zero', () => {
        fakeLayout((el, base) => (el.style.width === '0px' || el.style.width === '0' ? rect(0.5, 0.5, 0, 0) : base));

        const report = collectDeferredIntegrity();
        expect(report.findings.find((f) => f.code === INTEGRITY_CODES.DOMRECT_INCONSISTENT)).toEqual({ code: INTEGRITY_CODES.DOMRECT_INCONSISTENT });
        expect(domRectOf(report)).toMatchObject({ math: true, identical: true, ghost: false });
    });
});

// ---------------------------------------------------------------------------
// svg_text_inconsistent, end to end
// ---------------------------------------------------------------------------

function fakeSvg(length: (text: string, call: number) => number, bboxDelta = 0): void {
    onRealm((realm) => {
        let call = 0;
        const proto = realm.SVGElement.prototype as unknown as Record<string, unknown>;
        proto.getComputedTextLength = function (this: SVGElement) {
            return length(this.textContent ?? '', call++);
        };
        proto.getBBox = function (this: SVGElement) {
            return { x: 0, y: 0, width: length(this.textContent ?? '', -1) + bboxDelta, height: 20 };
        };
    });
}

describe('svg_text_inconsistent', () => {
    const honestLength = (text: string): number => text.length * 7.25;

    it('is silent on conformant metrics', () => {
        fakeSvg(honestLength);

        const report = collectDeferredIntegrity();
        expect(report.findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.SVG_TEXT_INCONSISTENT);
        const value = report.data.phantomRealm?.state === 'ok' ? (report.data.phantomRealm.value as PhantomRealmValue) : null;
        expect(value?.svgText).toEqual({ repeatEqual: true, bboxAgrees: true });
    });

    it('is silent at a 0.5 px bbox difference', () => {
        fakeSvg(honestLength, 0.5);

        expect(codes()).not.toContain(INTEGRITY_CODES.SVG_TEXT_INCONSISTENT);
    });

    it('FIRES when two reads of the same text differ (per-call noise)', () => {
        fakeSvg((text, call) => honestLength(text) + (call >= 0 ? call * 1e-3 : 0));

        const report = collectDeferredIntegrity();
        expect(report.findings.find((f) => f.code === INTEGRITY_CODES.SVG_TEXT_INCONSISTENT)).toEqual({ code: INTEGRITY_CODES.SVG_TEXT_INCONSISTENT });
        expect(svgTextOf(report)).toEqual({ repeatEqual: false, bboxAgrees: true });
    });

    it('FIRES when the bbox and the text length disagree by more than 0.5 px', () => {
        fakeSvg(honestLength, 0.75);

        const report = collectDeferredIntegrity();
        expect(report.findings.find((f) => f.code === INTEGRITY_CODES.SVG_TEXT_INCONSISTENT)).toEqual({ code: INTEGRITY_CODES.SVG_TEXT_INCONSISTENT });
        expect(svgTextOf(report)).toEqual({ repeatEqual: true, bboxAgrees: false });
    });
});

// ---------------------------------------------------------------------------
// screenTruth: data only
// ---------------------------------------------------------------------------

/** Make the iframe's computed custom properties on <html> read from `props`; other elements from `element`. */
function fakeComputed(props: Record<string, string>, element: Partial<CSSStyleDeclaration> = {}): void {
    onRealm((realm, doc) => {
        // jsdom implements constructable stylesheets but not `adoptedStyleSheets`; supply the
        // array so the probe takes the CSSOM path a browser takes.
        (doc as Document & { adoptedStyleSheets?: CSSStyleSheet[] }).adoptedStyleSheets = [];
        realm.getComputedStyle = ((el: Element) =>
            el === doc.documentElement
                ? ({ getPropertyValue: (name: string) => props[name] ?? '' } as unknown as CSSStyleDeclaration)
                : (element as CSSStyleDeclaration)) as typeof realm.getComputedStyle;
    });
}

describe('screenTruth', () => {
    const screenOf = (): unknown => {
        const value = realmValue();
        return value.screenTruth;
    };

    it('reports the CSS answer when the calibration rule matches', () => {
        fakeComputed({ '--nc-cw': '1', '--nc-ch': ' 1', '--nc-cd': '1', '--nc-w': '1', '--nc-h': '', '--nc-d': '1' });
        vi.spyOn(window, 'matchMedia').mockImplementation((query: string) => ({ matches: query.startsWith('(min-device-width') }) as MediaQueryList);

        expect(screenOf()).toEqual({ cssWidth: true, cssHeight: false, cssDpr: true, mediaWidth: true, mediaHeight: false, mediaDpr: false });
    });

    it('asks RANGE queries (±0.5 px, ±0.005 dppx), so the fractional Gecko device size at 125 % scaling still matches', () => {
        const asked: string[] = [];
        vi.spyOn(window, 'matchMedia').mockImplementation((query: string) => {
            asked.push(query);
            return { matches: true } as MediaQueryList;
        });
        defineOwn(window.screen, 'width', { get: () => 1536 });
        defineOwn(window.screen, 'height', { get: () => 864 });
        defineOwn(window, 'devicePixelRatio', { get: () => 1.25 });

        realmValue();

        expect(asked).toEqual([
            '(min-device-width: 1535.5px) and (max-device-width: 1536.5px)',
            '(min-device-height: 863.5px) and (max-device-height: 864.5px)',
            '(min-resolution: 1.245dppx) and (max-resolution: 1.255dppx)',
        ]);
    });

    it('reports null, not false, when the realm has no device size (WebKit subframes, RFP 0x0 frames)', () => {
        fakeComputed({ '--nc-cd': '1', '--nc-d': '1' });

        const truth = screenOf() as Record<string, unknown>;
        expect(truth.cssWidth).toBeNull();
        expect(truth.cssHeight).toBeNull();
        expect(truth.cssDpr).toBe(true);
    });

    it('is null throughout in jsdom, which has no adoptedStyleSheets: the rules cannot be installed, so nothing is measured', () => {
        const truth = screenOf() as Record<string, unknown>;
        expect([truth.cssWidth, truth.cssHeight, truth.cssDpr]).toEqual([null, null, null]);
    });

    it('never raises a finding, even when CSS and JS disagree on both dimensions', () => {
        fakeComputed({ '--nc-cw': '1', '--nc-ch': '1', '--nc-cd': '1' });

        const value = realmValue();
        expect(value.screenTruth).toMatchObject({ cssWidth: false, cssHeight: false });
        expect(phantomFindings(value)).toEqual([]);
    });
});

describe('the shared target list', () => {
    it('is the same list the realm comparison and the lie battery use', () => {
        const value = realmValue();
        const resolvable = LIE_TARGETS.filter((t) => {
            try {
                return typeof t.get() === 'function';
            } catch {
                return false;
            }
        }).length;

        expect(subValue(value.nativeToString)?.checked).toBe(resolvable);
    });
});

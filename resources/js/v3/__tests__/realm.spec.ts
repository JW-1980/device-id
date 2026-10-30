/**
 * The realm-independent reads shared by the window and the worker (`realm.ts`), and the
 * tier-1 `engineIdentity` probe built on them.
 *
 * The mark sets in the classifier table are not invented: each is the value
 * tests/Browser/transport-checks.mjs printed for that engine on 2026-10-05
 * (Chromium 153.0.8010.12, Firefox 155.0, WebKit 26.6). The live run below is the jsdom
 * environment, which executes on Node's V8, so it must classify as `v8`.
 */

import { afterEach, describe, expect, it } from 'vitest';
import {
    classifyEngine,
    engineIdentityOf,
    engineMarks,
    formatBrands,
    sanitiseReply,
    scopeSnapshot,
    stackShapeOf,
    SCOPE_REPLY_KIND,
    type EngineMarks,
    type ScopeSnapshot,
} from '@device-id/v3/realm';
import { engineIdentity, probesOf, TIER } from '@device-id/v3/value-probes';

const undos: Array<() => void> = [];
afterEach(() => {
    while (undos.length) undos.pop()?.();
});

/** Install `descriptor` as an own property of `target`, undone after the test. */
function defineOwn(target: object, name: string, descriptor: PropertyDescriptor): void {
    const original = Object.getOwnPropertyDescriptor(target, name);
    Object.defineProperty(target, name, { configurable: true, ...descriptor });
    undos.push(() => {
        if (original) Object.defineProperty(target, name, original);
        else delete (target as Record<string, unknown>)[name];
    });
}

const SNAPSHOT_KEYS = [
    'userAgent', 'platform', 'hardwareConcurrency', 'deviceMemory', 'language', 'languages',
    'timeZone', 'locale', 'tzOffset', 'uaPlatform', 'uaMobile', 'uaBrands', 'webglVendor',
    'webglRenderer', 'currencyCount', 'engine', 'canvasHash',
];

describe('classifyEngine', () => {
    // Observed marks, per engine (see the file docblock).
    const observed: Array<[string, Omit<EngineMarks, 'toFixedMessageLength'>, string]> = [
        ['Chromium 153 (V8)', { errorOwnProps: 'message,stack', stackShape: 'at', internalError: false }, 'v8'],
        ['Firefox 155 (SpiderMonkey)', { errorOwnProps: 'columnNumber,fileName,lineNumber,message', stackShape: 'at-sign', internalError: true }, 'spidermonkey'],
        ['WebKit 26.6 (JavaScriptCore)', { errorOwnProps: 'column,line,message,sourceURL,stack', stackShape: 'at-sign', internalError: false }, 'jsc'],
    ];

    for (const [label, marks, engine] of observed) {
        it(`maps the ${label} marks to '${engine}'`, () => {
            expect(classifyEngine(marks)).toBe(engine);
        });
    }

    it('applies each documented rule on its own, in the documented order', () => {
        // SpiderMonkey: any one of its three own properties, or InternalError alone.
        for (const prop of ['lineNumber', 'columnNumber', 'fileName']) {
            expect(classifyEngine({ errorOwnProps: `message,${prop}`, stackShape: 'other', internalError: false })).toBe('spidermonkey');
        }
        expect(classifyEngine({ errorOwnProps: 'message', stackShape: 'none', internalError: true })).toBe('spidermonkey');
        // SpiderMonkey wins over the JSC and V8 marks when both are present.
        expect(classifyEngine({ errorOwnProps: 'lineNumber,message,sourceURL,stack', stackShape: 'at', internalError: false })).toBe('spidermonkey');

        // JavaScriptCore: sourceURL alone, or line AND column. Not line alone.
        expect(classifyEngine({ errorOwnProps: 'message,sourceURL', stackShape: 'none', internalError: false })).toBe('jsc');
        expect(classifyEngine({ errorOwnProps: 'column,line,message', stackShape: 'none', internalError: false })).toBe('jsc');
        expect(classifyEngine({ errorOwnProps: 'line,message', stackShape: 'none', internalError: false })).toBe('unknown');
        // JSC wins over the V8 marks.
        expect(classifyEngine({ errorOwnProps: 'message,sourceURL,stack', stackShape: 'at', internalError: false })).toBe('jsc');

        // V8 needs BOTH the `at` frame syntax and an own `stack`.
        expect(classifyEngine({ errorOwnProps: 'message', stackShape: 'at', internalError: false })).toBe('unknown');
        expect(classifyEngine({ errorOwnProps: 'message,stack', stackShape: 'at-sign', internalError: false })).toBe('unknown');
        expect(classifyEngine({ errorOwnProps: 'message,stack', stackShape: 'none', internalError: false })).toBe('unknown');

        // Nothing at all is unknown, never a guess.
        expect(classifyEngine({ errorOwnProps: '', stackShape: 'none', internalError: false })).toBe('unknown');
    });

    it('matches whole property names, not substrings', () => {
        expect(classifyEngine({ errorOwnProps: 'message,myLineNumberish,stack', stackShape: 'at', internalError: false })).toBe('v8');
        expect(classifyEngine({ errorOwnProps: 'message,sourceURLs,stack', stackShape: 'at', internalError: false })).toBe('v8');
    });
});

describe('stackShapeOf', () => {
    it('skips the V8 header line and reads the first frame', () => {
        expect(stackShapeOf('Error: x\n    at engineMarks (http://h/collector.js:1:2)\n    at run (http://h/c.js:3:4)')).toBe('at');
    });

    it('reads SpiderMonkey and JavaScriptCore frames, which have no header', () => {
        expect(stackShapeOf('engineMarks@http://h/collector.js:1:2\nrun@http://h/c.js:3:4\n')).toBe('at-sign');
        expect(stackShapeOf('@http://h/collector.js:1:2')).toBe('at-sign');
    });

    it('is `none` without a stack, or with a header and no frame', () => {
        expect(stackShapeOf(undefined)).toBe('none');
        expect(stackShapeOf(42)).toBe('none');
        expect(stackShapeOf('')).toBe('none');
        expect(stackShapeOf('Error: x')).toBe('none');
        expect(stackShapeOf('Error: x\n\n')).toBe('none');
    });

    it('is `other` for a frame in neither syntax', () => {
        expect(stackShapeOf('Error: x\nsomething else entirely')).toBe('other');
    });
});

describe('engineIdentity (tier 1)', () => {
    it('is registered in tier 1 directly after architecture', () => {
        const names = probesOf(TIER.ONE).map((entry) => entry.name);
        expect(names.indexOf('engineIdentity')).toBe(names.indexOf('architecture') + 1);
    });

    it('reports the live V8 marks of the jsdom run (Node is V8) and classifies them as v8', () => {
        const result = engineIdentity();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        expect(result.value.errorOwnProps).toBe('message,stack');
        expect(result.value.stackShape).toBe('at');
        expect(result.value.internalError).toBe(false);
        expect(Number.isInteger(result.value.toFixedMessageLength)).toBe(true);
        expect(result.value.toFixedMessageLength).toBeGreaterThan(0);
        expect(result.value.engine).toBe('v8');
        expect(Object.keys(result.value).sort()).toEqual(['engine', 'errorOwnProps', 'internalError', 'stackShape', 'toFixedMessageLength']);
        // The verdict is a pure function of the marks sent with it.
        expect(classifyEngine(result.value)).toBe(result.value.engine);
    });

    it('reports -1 when (-1).toFixed(-1) does not throw, instead of failing the probe', () => {
        defineOwn(Number.prototype, 'toFixed', { value: () => '', writable: true });

        expect(engineMarks().toFixedMessageLength).toBe(-1);
        expect(engineIdentity().state).toBe('ok');
    });

    it('follows a mark a page could plant: an InternalError global turns the verdict to spidermonkey', () => {
        // Demonstrates why the server re-derives from the raw marks rather than trusting
        // `engine`: the marks are what is sent, and they say exactly why.
        defineOwn(globalThis, 'InternalError', { value: function InternalError() {}, writable: true });

        const identity = engineIdentityOf();
        expect(identity.internalError).toBe(true);
        expect(identity.engine).toBe('spidermonkey');
    });

    it('never throws when the Error constructor itself is hostile', () => {
        defineOwn(globalThis, 'Error', {
            value: function HostileError() {
                throw new TypeError('no errors for you');
            },
            writable: true,
        });

        const marks = engineMarks();
        // Restore before asserting: the test runner itself constructs Errors.
        undos.pop()?.();
        expect(marks.errorOwnProps).toBe('');
        expect(marks.stackShape).toBe('none');
    });
});

describe('formatBrands (GREASE removal)', () => {
    it('removes the GREASE brand in its rotating spellings, sorts, and joins brand/version', () => {
        expect(
            formatBrands([
                { brand: 'Not)A;Brand', version: '99' },
                { brand: 'Google Chrome', version: '153' },
                { brand: 'Chromium', version: '153' },
                { brand: 'Not_A Brand', version: '8' },
                { brand: 'NOT-A.BRAND', version: '24' },
            ]),
        ).toBe('Chromium/153,Google Chrome/153');
    });

    it('keeps brands that contain only one of the two words', () => {
        expect(formatBrands([{ brand: 'Brave', version: '1' }, { brand: 'Nothing', version: '2' }])).toBe('Brave/1,Nothing/2');
    });

    it('is independent of the (randomised) brand order', () => {
        const a = [{ brand: 'Chromium', version: '153' }, { brand: 'Microsoft Edge', version: '153' }];
        expect(formatBrands(a)).toBe(formatBrands([...a].reverse()));
    });

    it('is null for a non-array and drops malformed entries', () => {
        expect(formatBrands(undefined)).toBeNull();
        expect(formatBrands('Chromium')).toBeNull();
        expect(formatBrands([{ brand: 'Chromium', version: '153' }, { brand: 7 }, null, 'x'])).toBe('Chromium/153');
    });
});

describe('scopeSnapshot', () => {
    it('has exactly the contract keys and reads this realm', () => {
        const snapshot = scopeSnapshot({ vendor: 'V', renderer: 'R' }, null);

        expect(Object.keys(snapshot)).toEqual(SNAPSHOT_KEYS);
        expect(snapshot.userAgent).toBe(navigator.userAgent);
        expect(snapshot.language).toBe(navigator.language);
        expect(snapshot.languages).toBe(Array.from(navigator.languages).join(','));
        expect(snapshot.timeZone).toBe(Intl.DateTimeFormat().resolvedOptions().timeZone);
        expect(snapshot.webglVendor).toBe('V');
        expect(snapshot.webglRenderer).toBe('R');
        expect(snapshot.engine).toBe('v8');
    });

    it('reads the time-zone offset of a FIXED date, so DST does not change the claim', () => {
        expect(scopeSnapshot({ vendor: null, renderer: null }, null).tzOffset).toBe(new Date(2026, 0, 15).getTimezoneOffset());
    });

    it('removes the GREASE brand from userAgentData and reports platform and mobile', () => {
        defineOwn(navigator, 'userAgentData', {
            value: {
                brands: [{ brand: 'Not)A;Brand', version: '99' }, { brand: 'Chromium', version: '153' }],
                mobile: false,
                platform: 'Windows',
            },
        });

        const snapshot = scopeSnapshot({ vendor: null, renderer: null }, null);
        expect(snapshot.uaBrands).toBe('Chromium/153');
        expect(snapshot.uaPlatform).toBe('Windows');
        expect(snapshot.uaMobile).toBe(false);
    });

    it('turns each throwing or wrongly-typed field into null without losing the others', () => {
        defineOwn(navigator, 'userAgent', { get: () => { throw new Error('hostile'); } });
        defineOwn(navigator, 'hardwareConcurrency', { value: '8' });
        defineOwn(navigator, 'languages', { get: () => { throw new Error('hostile'); } });

        const snapshot = scopeSnapshot({ vendor: null, renderer: null }, null);
        expect(snapshot.userAgent).toBeNull();
        expect(snapshot.hardwareConcurrency).toBeNull();
        expect(snapshot.languages).toBeNull();
        expect(snapshot.platform).toBe(navigator.platform);
        expect(snapshot.uaBrands).toBeNull(); // jsdom has no userAgentData
    });
});

describe('sanitiseReply', () => {
    const valid: ScopeSnapshot = scopeSnapshot({ vendor: 'V', renderer: 'R' }, '0a1b2c3d');

    it('accepts a well-formed reply unchanged', () => {
        expect(sanitiseReply({ kind: SCOPE_REPLY_KIND, snapshot: valid })).toEqual(valid);
    });

    it('rejects anything that is not the reply envelope', () => {
        for (const bad of [null, undefined, 'scope', 42, {}, { kind: 'other', snapshot: valid }, { kind: SCOPE_REPLY_KIND }, { kind: SCOPE_REPLY_KIND, snapshot: null }]) {
            expect(sanitiseReply(bad)).toBeNull();
        }
    });

    it('re-types every field: a wrong type becomes null, an unknown engine becomes unknown, extra keys are dropped', () => {
        const result = sanitiseReply({
            kind: SCOPE_REPLY_KIND,
            snapshot: { ...valid, userAgent: 7, hardwareConcurrency: '8', uaMobile: 'false', tzOffset: Number.NaN, engine: 'chakra', injected: 'x' },
        });

        expect(result).not.toBeNull();
        expect(Object.keys(result as object)).toEqual(SNAPSHOT_KEYS);
        expect(result?.userAgent).toBeNull();
        expect(result?.hardwareConcurrency).toBeNull();
        expect(result?.uaMobile).toBeNull();
        expect(result?.tzOffset).toBeNull();
        expect(result?.engine).toBe('unknown');
        expect(result?.platform).toBe(valid.platform);
    });
});

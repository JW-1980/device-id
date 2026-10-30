/**
 * `lieBattery` and `resistance` (integrity.ts), and the per-method policy of
 * `collectIntegrity(disabled)`.
 *
 * Every lie code is shown to FIRE on a fake built to violate it — a `Proxy`-wrapped native,
 * a `function` closure, an arrow, a bound function, a function with an own `toString`, a
 * `Proxy` whose traps misbehave — and to stay SILENT on real native functions (Node's V8
 * natives here; jsdom's own WebIDL getters are JavaScript, which the tests account for). That
 * all 24-25 targets are clean in a stock Chromium, Firefox and WebKit is asserted against the
 * real engines in tests/Browser/transport-checks.mjs (check a).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
    collectDeferredIntegrity,
    collectIntegrity,
    INTEGRITY_CODES,
    LIE_CODES,
    lieBattery,
    lieCodesOf,
    resistance,
    TIMER_SPIN_CAP,
    timerGranularityUs,
} from '@device-id/collector/integrity';
import { LIE_TARGETS, type LieTarget } from '@device-id/collector/phantom';

const undos: Array<() => void> = [];
afterEach(() => {
    vi.restoreAllMocks();
    while (undos.length) undos.pop()?.();
});

/** Replace an own property for the duration of one test. */
function defineOwn(target: object, name: string, descriptor: PropertyDescriptor): void {
    const original = Object.getOwnPropertyDescriptor(target, name);
    Object.defineProperty(target, name, { configurable: true, ...descriptor });
    undos.push(() => {
        if (original) Object.defineProperty(target, name, original);
        else delete (target as Record<string, unknown>)[name];
    });
}

type AnyFn = (...args: never[]) => unknown;
const codesOf = (fn: unknown, name: string): string[] => lieCodesOf(fn as AnyFn, name);
const findingCodes = (disabled: readonly string[] = []): string[] => collectIntegrity(disabled).findings.map((f) => f.code);
/** `data.lieBattery.lied` (api -> comma-joined lie codes): what the server reads, since findings carry codes only. */
const liedOf = (report: ReturnType<typeof collectIntegrity>): Record<string, string> => {
    const data = report.data.lieBattery;
    return data?.state === 'ok' ? (data.value as { lied: Record<string, string> }).lied : {};
};

describe('lieCodesOf: native functions are clean', () => {
    it.each([
        ['sin', Math.sin],
        ['toString', Function.prototype.toString],
        ['getTimezoneOffset', Date.prototype.getTimezoneOffset],
        ['resolvedOptions', Intl.DateTimeFormat.prototype.resolvedOptions],
        ['keys', Object.keys],
    ])('%s violates nothing', (name, fn) => {
        expect(codesOf(fn, name)).toEqual([]);
    });

    it('leaves a native function exactly as it found it (the cycle attempt throws before mutating)', () => {
        codesOf(Math.sin, 'sin');

        expect(Object.getPrototypeOf(Math.sin)).toBe(Function.prototype);
        expect(Math.sin(0)).toBe(0);
    });

    it('requires the source name to be the member name', () => {
        // Math.sin is native, but it is not `cos`: a native function standing in for another.
        expect(codesOf(Math.sin, 'cos')).toEqual(['to_string']);
    });
});

describe('lieCodesOf: each code fires on a fake built to violate it', () => {
    it('a `function` closure: constructible, has a prototype, extra own keys, JS source', () => {
        const fake = function width(): number {
            return 1920;
        };

        expect(codesOf(fake, 'width')).toEqual(['new_instance', 'prototype_in', 'own_keys', 'descriptor_keys', 'to_string']);
    });

    it('an arrow function violates only to_string', () => {
        expect(codesOf(() => 1920, 'width')).toEqual(['to_string']);
    });

    it('a bound native violates only to_string: its source has no name', () => {
        expect(codesOf(Math.sin.bind(null), 'sin')).toEqual(['to_string']);
    });

    it('an own toString that returns native-looking text: own keys, and Object.create(fn).toString() no longer throws', () => {
        const fake = Object.assign(() => 1920, { toString: () => 'function get width() { [native code] }' });

        expect(codesOf(fake, 'width')).toEqual(['own_keys', 'descriptor_keys', 'to_string', 'object_to_string']);
    });

    it('a Proxy around a native survives a cyclic prototype — and the target is repaired at once', () => {
        const proxy = new Proxy(Math.cos, {});

        expect(codesOf(proxy, 'cos')).toEqual(['to_string', 'proto_cycle']);
        expect(Object.getPrototypeOf(Math.cos)).toBe(Function.prototype);
        expect(Math.cos(0)).toBe(1);
        expect(typeof Math.cos.call).toBe('function');
    });

    it('a Proxy whose get trap answers `arguments` violates arguments_access', () => {
        const proxy = new Proxy(Math.atan, {
            get: (target, key, receiver) => (key === 'arguments' ? null : Reflect.get(target, key, receiver)),
        });

        expect(codesOf(proxy, 'atan')).toEqual(['to_string', 'proto_cycle', 'arguments_access']);
        expect(Object.getPrototypeOf(Math.atan)).toBe(Function.prototype);
    });

    it('own_keys and descriptor_keys are separate reflection paths: an ownKeys trap can fool one only', () => {
        const proxy = new Proxy(Math.tan, { ownKeys: (target) => [...Reflect.ownKeys(target), 'extra'] });

        const codes = codesOf(proxy, 'tan');
        expect(codes).toContain('own_keys');
        expect(codes).not.toContain('descriptor_keys');
    });

    it('a setPrototypeOf trap that throws its own error is not native behaviour', () => {
        const proxy = new Proxy(Math.asin, {
            setPrototypeOf: () => {
                throw new RangeError('too much recursion');
            },
        });

        expect(codesOf(proxy, 'asin')).toContain('proto_cycle');
    });

    it('does not attempt the cycle on a non-extensible function (contract: only when extensible)', () => {
        const frozen = Object.preventExtensions(new Proxy(Math.acos, {}));

        expect(codesOf(frozen, 'acos')).not.toContain('proto_cycle');
    });

    it('an invariant whose evaluation throws counts as violated, and nothing propagates', () => {
        const proxy = new Proxy(Math.log, {
            has: () => {
                throw new Error('trap');
            },
        });

        expect(() => codesOf(proxy, 'log')).not.toThrow();
        expect(codesOf(proxy, 'log')).toContain('prototype_in');
    });

    it('a revoked proxy violates without throwing out of the battery', () => {
        const { proxy, revoke } = Proxy.revocable(() => 1, {});
        revoke();

        expect(() => codesOf(proxy, 'x')).not.toThrow();
        expect(codesOf(proxy, 'x').length).toBeGreaterThan(0);
    });

    it('reports codes in the documented order', () => {
        expect(LIE_CODES).toEqual(['new_instance', 'prototype_in', 'own_keys', 'descriptor_keys', 'to_string', 'object_to_string', 'proto_cycle', 'arguments_access']);
    });
});

describe('lieBattery', () => {
    const target = (api: string, get: () => unknown): LieTarget => ({ api, get });

    it('counts only targets that resolve to a function, and reports per api', () => {
        const result = lieBattery([
            target('Math.sin', () => Math.sin),
            target('Missing.gone', () => undefined),
            target('Data.value', () => 42),
            target('Throws.get', () => {
                throw new Error('no interface');
            }),
            target('Screen.width', () => new Proxy(Math.cos, {})),
        ]);

        expect(result).toEqual({ state: 'ok', value: { checked: 2, lied: { 'Screen.width': 'to_string,proto_cycle' } } });
    });

    it('covers the contract target list', () => {
        expect(LIE_TARGETS.map((t) => t.api)).toEqual([
            'Navigator.userAgent', 'Navigator.platform', 'Navigator.hardwareConcurrency', 'Navigator.deviceMemory',
            'Navigator.languages', 'Navigator.plugins', 'Navigator.webdriver', 'Screen.width', 'Screen.height',
            'HTMLCanvasElement.toDataURL', 'HTMLCanvasElement.getContext', 'HTMLCanvasElement.toBlob',
            'CanvasRenderingContext2D.getImageData', 'CanvasRenderingContext2D.fillText', 'CanvasRenderingContext2D.measureText',
            'WebGLRenderingContext.getParameter', 'WebGLRenderingContext.getExtension', 'WebGLRenderingContext.readPixels',
            'WebGL2RenderingContext.getParameter', 'WebGL2RenderingContext.getExtension', 'WebGL2RenderingContext.readPixels',
            'Date.getTimezoneOffset', 'Intl.DateTimeFormat.resolvedOptions', 'AudioBuffer.getChannelData', 'Permissions.query',
            'Function.toString', 'Math.sin', 'Element.getBoundingClientRect',
        ]);
    });

    it('resolves Function.prototype.toString, whose prototype object is itself a function', () => {
        const result = lieBattery(LIE_TARGETS.filter((t) => t.api === 'Function.toString' || t.api === 'Math.sin'));

        expect(result).toEqual({ state: 'ok', value: { checked: 2, lied: {} } });
    });

});

describe('lie_battery_failed through collectIntegrity', () => {
    const original = Object.getOwnPropertyDescriptor(Screen.prototype, 'width');

    it('FIRES in plain jsdom, whose WebIDL getters are JavaScript — and they violate only to_string', () => {
        const report = collectIntegrity();
        expect(report.findings.map((f) => f.code)).toContain(INTEGRITY_CODES.LIE_BATTERY_FAILED);

        const data = report.data.lieBattery;
        expect(data?.state).toBe('ok');
        if (data?.state !== 'ok') return;
        const value = data.value as { checked: number; lied: Record<string, string> };
        expect(value.checked).toBeGreaterThan(5);
        for (const codes of Object.values(value.lied)) expect(codes).toBe('to_string');
    });

    it('FIRES on a Proxy-wrapped Screen.width getter, naming the api and codes but no value', () => {
        expect(original?.get).toBeTypeOf('function');
        defineOwn(Screen.prototype, 'width', { get: new Proxy(original?.get as () => number, {}) });

        const report = collectIntegrity();
        const findings = report.findings.filter((f) => f.code === INTEGRITY_CODES.LIE_BATTERY_FAILED);
        // The finding is the bare code; the api and its codes are in the data the server reads.
        expect(findings).toEqual([{ code: INTEGRITY_CODES.LIE_BATTERY_FAILED }]);
        expect(liedOf(report)['Screen.width']).toBe('to_string,proto_cycle');
        expect(JSON.stringify(liedOf(report))).not.toMatch(/\d{3,}/);
        // The wrapped getter still works after the battery repaired it.
        expect(typeof screen.width).toBe('number');
    });

    it('FIRES on a `function` closure installed as a method', () => {
        defineOwn(HTMLCanvasElement.prototype, 'toDataURL', {
            value: function toDataURL(): string {
                return 'data:,';
            },
            writable: true,
        });

        const report = collectIntegrity();
        expect(report.findings.find((f) => f.code === INTEGRITY_CODES.LIE_BATTERY_FAILED)).toEqual({ code: INTEGRITY_CODES.LIE_BATTERY_FAILED });
        expect(liedOf(report)['HTMLCanvasElement.toDataURL']).toBe('new_instance,prototype_in,own_keys,descriptor_keys,to_string');
    });

    it('FIRES on an arrow-function getter, which violates only to_string (counted)', () => {
        defineOwn(Screen.prototype, 'width', { get: () => 1920 });

        const report = collectIntegrity();
        expect(report.findings.find((f) => f.code === INTEGRITY_CODES.LIE_BATTERY_FAILED)).toEqual({ code: INTEGRITY_CODES.LIE_BATTERY_FAILED });
        expect(liedOf(report)['Screen.width']).toBe('to_string');
    });

    it('stays silent on a native function installed as a getter replacement of the same name', () => {
        // A conformant fake: a real native function whose name matches the member.
        const lied = lieBattery([{ api: 'Math.sin', get: () => Math.sin }]);
        expect(lied).toEqual({ state: 'ok', value: { checked: 1, lied: {} } });
    });
});

// ---------------------------------------------------------------------------
// resistance
// ---------------------------------------------------------------------------

/** A clock that returns the scripted values in order, then repeats the last one. */
function scriptedClock(values: readonly number[]): () => number {
    let i = 0;
    return () => values[Math.min(i++, values.length - 1)] as number;
}

/** A clamped clock: advances by `tickMs` every `readsPerTick` reads, starting at `startMs`. */
function clampedClock(tickMs: number, readsPerTick: number, startMs = 1000): () => number {
    let reads = 0;
    return () => startMs + Math.floor(reads++ / readsPerTick) * tickMs;
}

describe('timerGranularityUs', () => {
    it.each([
        ['Chromium, 100 µs', 0.1, 100],
        ['Firefox and WebKit, 1 ms', 1, 1000],
        ['cross-origin-isolated Chromium, 5 µs', 0.005, 5],
    ])('returns the tick of a clamped clock (%s)', (_label, tickMs, expected) => {
        expect(timerGranularityUs(clampedClock(tickMs, 50))).toBe(expected);
    });

    it('absorbs float noise in the readings (Chromium: 40.40000000037253 → 40.5)', () => {
        expect(timerGranularityUs(scriptedClock([40.40000000037253, 40.40000000037253, 40.5, 40.60000000009313]))).toBe(100);
    });

    it('takes the smallest delta, so one pre-empted read spanning two ticks does not decide it', () => {
        expect(timerGranularityUs(scriptedClock([10, 10, 12, 13]))).toBe(1000);
    });

    it('keeps reading past the minimum read count until a SECOND boundary: a pre-empted first crossing is not the answer', () => {
        // 10 → 12 is two ticks (a read pre-empted across a boundary); 12 → 13, a hundred reads
        // later, is the real tick.
        expect(timerGranularityUs(scriptedClock([10, 12, ...Array(100).fill(12), 13]))).toBe(1000);
    });

    it('returns the smallest delta, not the last one', () => {
        expect(timerGranularityUs(scriptedClock([10, 11, ...Array(100).fill(11), 13]))).toBe(1000);
    });

    it('stops spinning once two boundaries are crossed and the minimum read count is reached', () => {
        let reads = 0;
        const clock = clampedClock(1, 10);
        timerGranularityUs(() => {
            reads++;
            return clock();
        });

        expect(reads).toBeLessThan(200);
    });

    it('uses one crossing when the cap is reached with only one', () => {
        const values = [0.5, ...Array(TIMER_SPIN_CAP - 1).fill(0.5), 17.1670];
        // One crossing at the very end of the spin: 16.667 ms.
        expect(timerGranularityUs(scriptedClock(values))).toBe(16667);
    });

    it.each([
        ['RFP 1/60 s', 333.34, 16667],
        ['Tor 100 ms', 300, 100000],
        ['an unrecognised coarse reading', 1234.5, null],
        ['a zero reading', 0, null],
    ])('recognises a coarse tick from a single reading when no boundary is crossed (%s)', (_label, reading, expected) => {
        expect(timerGranularityUs(() => reading)).toBe(expected);
    });

    it('reads at most TIMER_SPIN_CAP + 1 times on a clock that never moves', () => {
        let reads = 0;
        timerGranularityUs(() => {
            reads++;
            return 5;
        });

        expect(reads).toBe(TIMER_SPIN_CAP + 1);
    });

    it('is 0 and repeatable for Node’s unclamped clock, so the jsdom collection stays deterministic', () => {
        expect(timerGranularityUs()).toBe(0);
        expect(timerGranularityUs()).toBe(0);
    });
});

describe('resistance', () => {
    it('reports a stock non-Gecko engine (jsdom on V8) as no privacy tool', () => {
        expect(resistance()).toEqual({
            state: 'ok',
            value: { brave: false, timerGranularityUs: 0, rfp: false, tor: false, gecko: false },
        });
    });

    it('detects Brave by navigator.brave.isBrave, without calling it', () => {
        const isBrave = vi.fn(async () => true);
        defineOwn(navigator, 'brave', { value: { isBrave } });

        const result = resistance();
        expect(result.state === 'ok' && result.value.brave).toBe(true);
        expect(isBrave).not.toHaveBeenCalled();
    });

    it('is not Brave when navigator.brave lacks isBrave', () => {
        defineOwn(navigator, 'brave', { value: {} });

        const result = resistance();
        expect(result.state === 'ok' && result.value.brave).toBe(false);
    });

    it('reports brave as null, not false, when reading it throws', () => {
        defineOwn(navigator, 'brave', {
            get: () => {
                throw new Error('blocked');
            },
        });

        const result = resistance();
        expect(result.state === 'ok' && result.value.brave).toBe(null);
    });

    describe('under Gecko engine marks', () => {
        const actAsGecko = (): void => defineOwn(globalThis, 'InternalError', { value: function InternalError() {}, writable: true });

        it('rfp: Gecko with a 1/60 s clock', () => {
            actAsGecko();
            vi.spyOn(performance, 'now').mockReturnValue(333.34);

            const result = resistance();
            expect(result.state === 'ok' && result.value).toMatchObject({ gecko: true, timerGranularityUs: 16667, rfp: true });
        });

        it('not rfp: Gecko with Firefox’s stock 1 ms clock', () => {
            actAsGecko();
            const clock = clampedClock(1, 20);
            vi.spyOn(performance, 'now').mockImplementation(clock);

            const result = resistance();
            expect(result.state === 'ok' && result.value).toMatchObject({ gecko: true, timerGranularityUs: 1000, rfp: false });
        });

        it('not rfp: a coarse clock on a NON-Gecko engine', () => {
            vi.spyOn(performance, 'now').mockReturnValue(333.34);

            const result = resistance();
            expect(result.state === 'ok' && result.value).toMatchObject({ gecko: false, rfp: false });
        });

        it('tor: Gecko with RTCRtpTransceiver, MediaDevices and Credential all absent', () => {
            actAsGecko();
            for (const name of ['RTCRtpTransceiver', 'MediaDevices', 'Credential']) expect(name in globalThis).toBe(false);

            const result = resistance();
            expect(result.state === 'ok' && result.value.tor).toBe(true);
        });

        it.each(['RTCRtpTransceiver', 'MediaDevices', 'Credential'])('not tor when %s exists', (name) => {
            actAsGecko();
            defineOwn(globalThis, name, { value: function Present() {}, writable: true });

            const result = resistance();
            expect(result.state === 'ok' && result.value.tor).toBe(false);
        });
    });

    it('never raises a finding, even for Brave + RFP + Tor marks', () => {
        const baseline = findingCodes();

        defineOwn(navigator, 'brave', { value: { isBrave: () => Promise.resolve(true) } });
        defineOwn(globalThis, 'InternalError', { value: function InternalError() {}, writable: true });
        vi.spyOn(performance, 'now').mockReturnValue(300);

        const report = collectIntegrity();
        const data = report.data.resistance;
        expect(data?.state === 'ok' && data.value).toMatchObject({ brave: true, rfp: true, tor: true, timerGranularityUs: 100000 });
        expect(report.findings.map((f) => f.code)).toEqual(baseline);
    });
});

// ---------------------------------------------------------------------------
// per-method policy
// ---------------------------------------------------------------------------

const SYNC_KEYS = [
    'wrongReceiver', 'descriptorIntegrity', 'mathDual', 'canvasDual', 'domBlockers', 'webdriverPresence', 'canvasFill',
    'canvasPattern', 'automationMarks', 'lieBattery', 'resistance',
];
const DEFERRED_KEYS = ['phantomRealm', 'resistance', 'canvasFill', 'canvasPattern'];
const PHANTOM_CODES: string[] = [
    INTEGRITY_CODES.REALM_TOSTRING_MISMATCH, INTEGRITY_CODES.DOMRECT_INCONSISTENT, INTEGRITY_CODES.SVG_TEXT_INCONSISTENT,
];

describe('collectIntegrity(disabled): the synchronous phase', () => {
    it('runs everything but phantomRealm by default, in a stable key order', () => {
        expect(Object.keys(collectIntegrity().data)).toEqual(SYNC_KEYS);
    });

    it('skips each toggleable probe by its registry name: absent from data', () => {
        for (const name of ['mathDual', 'canvasDual', 'domBlockers', 'canvasFill', 'canvasPattern', 'automationMarks', 'lieBattery']) {
            expect(Object.keys(collectIntegrity([name]).data), name).toEqual(SYNC_KEYS.filter((key) => key !== name));
        }
    });

    it('never skips the core probes, even when named, nor webdriverPresence, which has no registry name', () => {
        const keys = Object.keys(collectIntegrity([...SYNC_KEYS, 'phantomRealm']).data);

        // `resistance` is core since the five-review round: it gates the trust projection.
        expect(keys).toEqual(['wrongReceiver', 'descriptorIntegrity', 'webdriverPresence', 'resistance']);
    });

    it('ignores unknown names and survives malformed input', () => {
        expect(Object.keys(collectIntegrity(['nope', 'LIEBATTERY', '']).data)).toEqual(SYNC_KEYS);
        expect(Object.keys(collectIntegrity(null as unknown as string[]).data)).toEqual(SYNC_KEYS);
        expect(Object.keys(collectIntegrity([42, null, 'lieBattery'] as unknown as string[]).data)).toEqual(SYNC_KEYS.filter((k) => k !== 'lieBattery'));
    });

    it('raises no phantom-realm code, even when the realm would', () => {
        // A page toString that lies about a patched getter: the deferred phase catches it,
        // the synchronous one never creates the realm at all.
        const fake = (): number => 1920;
        defineOwn(Screen.prototype, 'width', { get: fake });
        const pristine = Function.prototype.toString;
        let sync: string[];
        let deferred: string[];
        Function.prototype.toString = function toString(this: unknown): string {
            return this === fake ? 'function get width() { [native code] }' : pristine.call(this);
        };
        try {
            sync = collectIntegrity().findings.map((f) => f.code);
            deferred = collectDeferredIntegrity().findings.map((f) => f.code);
        } finally {
            Function.prototype.toString = pristine;
        }

        expect(sync.filter((code) => PHANTOM_CODES.includes(code))).toEqual([]);
        expect(deferred).toEqual([INTEGRITY_CODES.REALM_TOSTRING_MISMATCH]);
    });

    it('a skipped probe raises nothing, even on the tampering it would catch', () => {
        const original = Object.getOwnPropertyDescriptor(Screen.prototype, 'width');
        defineOwn(Screen.prototype, 'width', { get: new Proxy(original?.get as () => number, {}) });

        const on = collectIntegrity([]);
        expect(on.findings.find((f) => f.code === INTEGRITY_CODES.LIE_BATTERY_FAILED)).toEqual({ code: INTEGRITY_CODES.LIE_BATTERY_FAILED });
        expect(liedOf(on)['Screen.width']).toBe('to_string,proto_cycle');

        const off = collectIntegrity(['lieBattery']);
        expect(off.findings.find((f) => f.code === INTEGRITY_CODES.LIE_BATTERY_FAILED)).toBeUndefined();
        expect(off.data.lieBattery).toBeUndefined();
    });

    it('a skipped probe does not affect the others (math still fires when canvas is off)', () => {
        defineOwn(Math, 'tanh', { value: () => 0.5, writable: true });

        expect(findingCodes(['canvasDual', 'canvasFill'])).toContain(INTEGRITY_CODES.MATH_PF_MISMATCH);
        expect(findingCodes(['mathDual'])).not.toContain(INTEGRITY_CODES.MATH_PF_MISMATCH);
    });

    it('exports the four new codes with their exact wire spelling', () => {
        expect(INTEGRITY_CODES.LIE_BATTERY_FAILED).toBe('lie_battery_failed');
        expect(INTEGRITY_CODES.REALM_TOSTRING_MISMATCH).toBe('realm_tostring_mismatch');
        expect(INTEGRITY_CODES.DOMRECT_INCONSISTENT).toBe('domrect_inconsistent');
        expect(INTEGRITY_CODES.SVG_TEXT_INCONSISTENT).toBe('svg_text_inconsistent');
    });
});

describe('collectDeferredIntegrity(disabled): the deferred phase', () => {
    it('runs phantomRealm, resistance, canvasFill and canvasPattern, in that order, and nothing else', () => {
        const report = collectDeferredIntegrity();

        expect(Object.keys(report.data)).toEqual(DEFERRED_KEYS);
        expect(typeof report.elapsedMs).toBe('number');
    });

    it('raises only phantom-realm codes — never canvas_readback_perturbed, which the sync phase already raised', () => {
        // A perturbed read-back: every pixel off by one in red.
        defineOwn(HTMLCanvasElement.prototype, 'getContext', {
            value: function getContext() {
                return {
                    fillStyle: '',
                    fillRect: () => undefined,
                    getImageData: (_x: number, _y: number, w: number, h: number) => {
                        const data = new Uint8ClampedArray(w * h * 4);
                        for (let i = 0; i < data.length; i += 4) data.set([11, 20, 30, 255], i);
                        return { data };
                    },
                };
            },
            writable: true,
        });

        const sync = collectIntegrity().findings.map((f) => f.code);
        const deferred = collectDeferredIntegrity();
        expect(sync).toContain(INTEGRITY_CODES.CANVAS_READBACK_PERTURBED);
        expect(deferred.data.canvasFill).toEqual({ state: 'ok', value: { exact: false, deviations: 3844 } });
        for (const code of deferred.findings.map((f) => f.code)) expect(PHANTOM_CODES).toContain(code);
        expect(deferred.findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.CANVAS_READBACK_PERTURBED);
    });

    it('carries resistance as data with no finding', () => {
        defineOwn(navigator, 'brave', { value: { isBrave: () => Promise.resolve(true) } });

        const report = collectDeferredIntegrity();
        const data = report.data.resistance;
        expect(data?.state === 'ok' && (data.value as { brave: boolean }).brave).toBe(true);
        expect(report.findings).toEqual([]);
    });

    it('skips each of its toggleable probes by registry name, keeps the core resistance, and ignores names it does not run', () => {
        for (const name of DEFERRED_KEYS.filter((key) => key !== 'resistance')) {
            expect(Object.keys(collectDeferredIntegrity([name]).data), name).toEqual(DEFERRED_KEYS.filter((key) => key !== name));
        }
        expect(Object.keys(collectDeferredIntegrity([...DEFERRED_KEYS]).data)).toEqual(['resistance']);
        expect(Object.keys(collectDeferredIntegrity(['lieBattery', 'nope']).data)).toEqual(DEFERRED_KEYS);
        expect(Object.keys(collectDeferredIntegrity(undefined as unknown as string[]).data)).toEqual(DEFERRED_KEYS);
    });

    it('a skipped phantomRealm raises nothing, even on the tampering it would catch', () => {
        const fake = (): number => 1920;
        defineOwn(Screen.prototype, 'width', { get: fake });
        const pristine = Function.prototype.toString;
        let on: string[];
        let off: string[];
        Function.prototype.toString = function toString(this: unknown): string {
            return this === fake ? 'function get width() { [native code] }' : pristine.call(this);
        };
        try {
            on = collectDeferredIntegrity().findings.map((f) => f.code);
            off = collectDeferredIntegrity(['phantomRealm']).findings.map((f) => f.code);
        } finally {
            Function.prototype.toString = pristine;
        }

        expect(on).toEqual([INTEGRITY_CODES.REALM_TOSTRING_MISMATCH]);
        expect(off).toEqual([]);
    });
});

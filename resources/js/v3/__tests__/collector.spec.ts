/**
 * The browser-side fingerprint collector.
 *
 * ## What these tests can and cannot say
 *
 * This suite runs under jsdom, which is not a browser: no `AudioContext`, no WebGL, no
 * canvas 2D context, a `matchMedia` that returns `false` for everything. Asserting that
 * `wrongReceiver()` reports `threw:TypeError` here would be asserting a fact about jsdom.
 *
 * So the tests check what is true in any environment: no probe throws, every result is
 * tagged, the wire shapes match protocol v3, the canonical encoding keeps its
 * invariants, and — through fakes installed on the page — that the probes transform
 * their inputs correctly and that the integrity probes DO fire on the spoofs they are
 * meant to catch. What genuinely needs a real engine (zero integrity findings, budgets,
 * cross-engine agreement of the hardware probes) is asserted in
 * tests/Browser/transport-checks.mjs against Chromium, Firefox and WebKit.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { canonicalise, probe, probeAsync, claimDigest, sha256Hex, ok, failed, fnv1a32 } from '@device-id/v3/canonical';
import {
    collectIntegrity,
    wrongReceiver,
    descriptorIntegrity,
    mathDual,
    canvasDual,
    domBlockers,
    INTEGRITY_CODES,
} from '@device-id/v3/integrity';
import {
    VALUE_PROBES,
    TIER,
    dateParsing,
    cssMedia,
    esFeatures,
    textMetrics,
    errorText,
    environment,
    codecs,
    audioRealtime,
    uaClientHints,
    architecture,
    fontMetrics,
    emojiMetrics,
    scripts,
    gpu,
    audioHardware,
    decoders,
    voices,
    permissions,
    intl,
    normaliseRenderer,
    runTierChunked,
    probesOf,
    fontMetricsSteps,
    fontMetricsChunks,
    FONT_METRICS_FAMILIES,
    FONT_METRICS_STEPS,
    scriptsSteps,
    SCRIPT_SAMPLES,
    SCRIPTS_STEPS,
    EMOJI_SAMPLE,
    webgpuAdapter,
    resetWebgpuAdapterForTests,
} from '@device-id/v3/value-probes';
import { releaseShared } from '@device-id/v3/shared';
import { collect, collectTier2, scheduleTier2, collectAndSend, collectAndSendDetailed, requestChallenge, BUDGET_MS } from '@device-id/v3/index';
import { buildEnvelope, buildDecline, sendClaims, payloadBytes, TRANSPORT_LIMITS } from '@device-id/v3/transport';
import { FINGERPRINT_VERSION, PROBE_SET, type Challenge } from '@device-id/v3/protocol';

/** The shape `FingerprintChallengeController` issues: `{ token, purpose, expires_at }`. */
const CHALLENGE: Challenge = {
    token: 'test-token-not-a-real-secret',
    purpose: 'signin',
    expiresAt: Date.now() + 300_000,
};

/** Registry order of the hardware tier; `audioHardware` is last there (scheduled late, decision G-D5i). */
const HARDWARE_PROBES = ['fontMetrics', 'emojiMetrics', 'scripts', 'gpu', 'gpuMath', 'decoders', 'voices', 'fontFaces', 'keyboardLayout', 'parallelism', 'audioHardware'];

/** Install a value as an own property of `target`, returning an undo function. */
function defineOwn(target: object, name: string, value: unknown): () => void {
    const original = Object.getOwnPropertyDescriptor(target, name);
    Object.defineProperty(target, name, { value, configurable: true, writable: true });

    return () => {
        if (original) {
            Object.defineProperty(target, name, original);
        } else {
            delete (target as Record<string, unknown>)[name];
        }
    };
}

/**
 * A fake 2D context whose `measureText` width is a deterministic function of the font
 * string, so the width-probing font and script probes can be tested without a canvas.
 */
function installFakeCanvas(widthOf: (font: string, text: string) => number): () => void {
    const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
    const original = proto.getContext;
    proto.getContext = function fakeGetContext(kind: string): unknown {
        if (kind !== '2d') return null;
        const context = {
            font: '',
            measureText(text: string) {
                const width = widthOf(this.font, text);
                return {
                    width,
                    actualBoundingBoxAscent: width / 2,
                    actualBoundingBoxDescent: 0,
                    actualBoundingBoxLeft: 0,
                    actualBoundingBoxRight: width,
                };
            },
        };
        return context;
    };

    return () => {
        proto.getContext = original;
    };
}

/** A recording `fetch`: every call is captured, the challenge endpoint answers a token. */
function installRecordingFetch(challengeToken = 'issued-token'): { calls: Array<{ url: string; body: unknown }>; undo: () => void } {
    const calls: Array<{ url: string; body: unknown }> = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : null;
        calls.push({ url, body });
        if (url.endsWith('/challenge')) {
            return new Response(JSON.stringify({ token: challengeToken, purpose: 'signin', expires_at: 0 }), {
                status: 200,
                headers: { 'content-type': 'application/json' },
            });
        }
        return new Response('{"ok":true}', { status: 200 });
    }) as typeof fetch;

    return {
        calls,
        undo: () => {
            globalThis.fetch = original;
        },
    };
}

describe('canonicalise', () => {
    it('distinguishes values that JSON.stringify would merge', () => {
        expect(canonicalise(1)).not.toBe(canonicalise('1'));
        expect(canonicalise(0)).not.toBe(canonicalise(false));
        expect(canonicalise(null)).not.toBe(canonicalise(undefined));
    });

    it('distinguishes negative zero from zero', () => {
        expect(canonicalise(-0)).not.toBe(canonicalise(0));
        expect(canonicalise(NaN)).toBe('d:NaN');
        expect(canonicalise(Infinity)).toBe('d:Infinity');
    });

    it('sorts object keys at every depth', () => {
        const a = { outer: { b: 1, a: 2 }, list: [3, 1, 2] };
        const b = { list: [3, 1, 2], outer: { a: 2, b: 1 } };

        expect(canonicalise(a)).toBe(canonicalise(b));
    });

    it('preserves array order, because order is the signal in several probes', () => {
        expect(canonicalise([3, 1, 2])).not.toBe(canonicalise([1, 2, 3]));
    });

    it('is deterministic across repeated calls', () => {
        const value = { z: [1, { b: 2, a: 1 }], a: 'x' };

        expect(canonicalise(value)).toBe(canonicalise(value));
    });

    it('type-tags the new hardware probe values so a string count never equals a number count', () => {
        expect(canonicalise({ count: 2, pairs: '605:1181,702:958' })).toBe('{"count":d:2,"pairs":s:605:1181,702:958}');
        expect(canonicalise({ count: '2', pairs: '605:1181,702:958' })).not.toBe(canonicalise({ count: 2, pairs: '605:1181,702:958' }));
        expect(canonicalise({ nanSign: 'x86' })).toBe('{"nanSign":s:x86}');
        expect(canonicalise({ bits: '0110' })).toBe('{"bits":s:0110}');
        expect(canonicalise({ h264: '110', vp9: '000', av1: 'err' })).toBe('{"av1":s:err,"h264":s:110,"vp9":s:000}');
        expect(canonicalise({ webgpu: null, webgl: { limits: { MAX_TEXTURE_SIZE: 8192 } } })).toBe(
            '{"webgl":{"limits":{"MAX_TEXTURE_SIZE":d:8192}},"webgpu":n}',
        );
    });
});

describe('probe wrappers', () => {
    it('tags a thrown error instead of propagating it', () => {
        const result = probe('throwing', () => {
            throw new TypeError('boom');
        });

        expect(result.state).toBe('error');
        if (result.state === 'error') {
            expect(result.name).toBe('TypeError');
        }
    });

    it('wraps a rejected promise without propagating', async () => {
        const result = await probeAsync('rejecting', () => Promise.reject(new RangeError('nope')));

        expect(result.state).toBe('error');
    });

    it('wraps a promise that throws synchronously', async () => {
        const result = await probeAsync('sync-throw', () => {
            throw new Error('immediate');
        });

        expect(result.state).toBe('error');
    });

    it('passes values through untouched', () => {
        expect(probe('fine', () => 42)).toEqual(ok(42));
        expect(failed(new Error('x'))).toEqual({ state: 'error', name: 'Error' });
    });
});

describe('integrity probes', () => {
    const probes = { wrongReceiver, descriptorIntegrity, mathDual, canvasDual, domBlockers };

    for (const [name, run] of Object.entries(probes)) {
        it(`${name} returns a tagged result without throwing`, () => {
            const result = run();

            expect(['ok', 'unavailable', 'error']).toContain(result.state);
        });
    }

    it('wrongReceiver reports a verdict for every target it checks', () => {
        const result = wrongReceiver();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        const targets = Object.keys(result.value);
        expect(targets.length).toBeGreaterThan(8);
        for (const verdict of Object.values(result.value)) {
            expect(typeof verdict).toBe('string');
        }
    });

    it('mathDual produces its agreement flags, and they agree in a real engine', () => {
        const result = mathDual();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        for (const flag of ['atanhAgrees', 'tanhAgrees', 'expm1Agrees', 'asinhAgrees'] as const) {
            expect(result.value[flag]).toBe(true);
        }
    });

    it('descriptorIntegrity covers the properties a spoofer targets', () => {
        const result = descriptorIntegrity();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        for (const name of ['userAgent', 'platform', 'webdriver', 'plugins', 'hardwareConcurrency']) {
            expect(result.value[name]).toBeDefined();
        }
    });

    it('collectIntegrity always returns a findings array, even on total failure', () => {
        const report = collectIntegrity();

        expect(Array.isArray(report.findings)).toBe(true);
        expect(typeof report.elapsedMs).toBe('number');
    });

    it('domBlockers asks PerformanceObserver.supportedEntryTypes instead of observing an unknown type', () => {
        const observe = vi.fn();
        const undo = defineOwn(globalThis, 'PerformanceObserver', Object.assign(class {
            observe = observe;
        }, { supportedEntryTypes: ['longtask'] }));
        try {
            const result = domBlockers();
            expect(result.state).toBe('ok');
            if (result.state !== 'ok') return;
            expect(result.value.performanceObserverEntryTypes).toBe('unsupported');
            expect(observe).not.toHaveBeenCalled();
        } finally {
            undo();
        }
    });

    describe('against spoofers', () => {
        const undos: Array<() => void> = [];
        afterEach(() => {
            while (undos.length) undos.pop()?.();
        });

        it('reports an own property defined on the navigator instance as shadowed, and raises a finding', () => {
            // The cheapest measured bypass: one line, prototype untouched.
            undos.push(defineOwn(navigator, 'userAgent', 'Mozilla/5.0 (Spoofed)'));
            undos.push(defineOwn(navigator, 'hardwareConcurrency', 64));

            const shapes = descriptorIntegrity();
            expect(shapes.state).toBe('ok');
            if (shapes.state !== 'ok') return;
            expect(shapes.value.userAgent?.endsWith('o')).toBe(true);
            expect(shapes.value.hardwareConcurrency?.endsWith('o')).toBe(true);
            expect(shapes.value.platform?.endsWith('o')).toBe(false);

            const report = collectIntegrity();
            const shadowed = report.findings.filter((f) => f.code === INTEGRITY_CODES.DESCRIPTOR_SHADOWED);
            // One finding per shadowed attribute (the server's penalty counts entries), each the
            // bare code: which attributes is in `data.descriptorIntegrity`, asserted above.
            expect(shadowed).toEqual([{ code: INTEGRITY_CODES.DESCRIPTOR_SHADOWED }, { code: INTEGRITY_CODES.DESCRIPTOR_SHADOWED }]);
        });

        it('reports a plain-closure getter patched onto Navigator.prototype as non-native and receiver-blind', () => {
            const original = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent');
            expect(original?.get).toBeTypeOf('function');
            Object.defineProperty(Navigator.prototype, 'userAgent', {
                get: () => 'Mozilla/5.0 (Patched)',
                configurable: true,
            });
            undos.push(() => Object.defineProperty(Navigator.prototype, 'userAgent', original as PropertyDescriptor));

            const report = collectIntegrity();
            const codes = report.findings.map((f) => f.code);
            expect(codes).toContain(INTEGRITY_CODES.DESCRIPTOR_PATCHED);
            expect(codes).toContain(INTEGRITY_CODES.WRONG_RECEIVER_OK);

            const shapes = descriptorIntegrity();
            if (shapes.state === 'ok') {
                expect(shapes.value.userAgent?.startsWith('P')).toBe(true);
            }
        });

        it('reports a deleted webdriver attribute as missing', () => {
            const original = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
            if (!original) return; // jsdom without webdriver: nothing to delete
            delete (Navigator.prototype as unknown as Record<string, unknown>).webdriver;
            undos.push(() => Object.defineProperty(Navigator.prototype, 'webdriver', original));
            undos.push(defineOwn(navigator, 'webdriver', false));

            const codes = collectIntegrity().findings.map((f) => f.code);
            expect(codes).toContain(INTEGRITY_CODES.DESCRIPTOR_MISSING);
        });
    });
});

describe('value probes', () => {
    it('still reports brands when getHighEntropyValues is missing or throws', async () => {
        const plausible = [
            { brand: 'Chromium', version: '141' },
            { brand: 'Not)A;Brand', version: '24' },
        ];
        const undos: Array<() => void> = [];
        const setUserAgentData = (value: unknown): void => {
            undos.push(defineOwn(navigator, 'userAgentData', value));
        };

        try {
            // (a) No method at all: the bypass as described in the probe's docblock.
            setUserAgentData({ brands: plausible, mobile: false, platform: 'Windows' });
            let result = (await uaClientHints()) as { state: string; value: Record<string, unknown> };
            expect(result.state).toBe('ok');
            expect(result.value.brands).toEqual(plausible);
            expect(result.value.high).toBeNull();

            // (b) The method exists and rejects.
            setUserAgentData({
                brands: plausible,
                mobile: false,
                platform: 'Windows',
                getHighEntropyValues: () => Promise.reject(new Error('nope')),
            });
            result = (await uaClientHints()) as { state: string; value: Record<string, unknown> };
            expect(result.state).toBe('ok');
            expect(result.value.brands).toEqual(plausible);
            expect(result.value.high).toBeNull();

            // (c) A `brands` getter that throws: the other fields survive it.
            setUserAgentData({
                get brands(): never { throw new Error('nope'); },
                mobile: false,
                platform: 'Windows',
                getHighEntropyValues: () => Promise.resolve({ uaFullVersion: '141.0.0.0' }),
            });
            result = (await uaClientHints()) as { state: string; value: Record<string, unknown> };
            expect(result.state).toBe('ok');
            expect(result.value.brands).toBeNull();
            expect(result.value.platform).toBe('Windows');
            expect(result.value.high).toEqual({ uaFullVersion: '141.0.0.0' });

            // (d) Genuinely absent, which is Firefox and Safari.
            setUserAgentData(undefined);
            result = (await uaClientHints()) as { state: string; value: Record<string, unknown> };
            expect(result.value.supported).toBe(false);
        } finally {
            while (undos.length) undos.pop()?.();
        }
        expect(Object.prototype.hasOwnProperty.call(navigator, 'userAgentData')).toBe(false);
    });

    it('every registered probe returns a tagged result without throwing', async () => {
        for (const entry of VALUE_PROBES) {
            const result = await entry.run();
            expect(['ok', 'unavailable', 'error'], `${entry.name} produced an unexpected state`).toContain(
                (result as { state: string }).state,
            );
        }
    });

    it('records a tier for every probe, and the hardware probes are in the hardware tier', () => {
        for (const entry of VALUE_PROBES) {
            expect([TIER.ONE, TIER.TWO, TIER.HARDWARE]).toContain(entry.tier);
        }
        expect(probesOf(TIER.HARDWARE).map((entry) => entry.name)).toEqual(HARDWARE_PROBES);
        expect(probesOf(TIER.ONE).map((entry) => entry.name)).toContain('architecture');
    });

    it('registers no probe whose measured discrimination was zero', () => {
        const names = VALUE_PROBES.map((entry) => entry.name);
        for (const struck of ['asyncOrder', 'mapOrder', 'regexpFeatures', 'jsonEdge', 'typedArray', 'math']) {
            expect(names).not.toContain(struck);
        }
    });

    it('dateParsing covers the fallback-parser edge cases', () => {
        const result = dateParsing();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        expect(result.value['2024-01-15T10:20:30Z']).toBeDefined();
        expect(result.value['2024-13-45']).toBe('NaN');
    });

    it('dateParsing is stable across calls', () => {
        const first = dateParsing();
        const second = dateParsing();
        if (first.state !== 'ok' || second.state !== 'ok') return;

        expect(canonicalise(first.value)).toBe(canonicalise(second.value));
    });

    it('cssMedia returns a fixed-width bit string', () => {
        const result = cssMedia();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        expect(result.value).toHaveLength(24);
        expect(result.value).toMatch(/^[01x]+$/);
    });

    it('esFeatures reports a present count consistent with its list, tests instance-only members on an instance, and has no phantom API', () => {
        const result = esFeatures();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        const listed = result.value.present === '' ? [] : result.value.present.split(',');
        expect(result.value.count).toBe(listed.length);
        // `cause` and `errors` are own properties of instances, never on the prototype:
        // the old `in Error.prototype` checks were always 0 in every engine.
        expect(listed).toContain('errorCause');
        expect(listed).toContain('errorErrors');
        expect(listed).not.toContain('navModelId');
    });

    it('has no stackDepth probe any more (round-2 STD-3: a constant in V8, call-site dependent elsewhere)', () => {
        expect(VALUE_PROBES.map((entry) => entry.name)).not.toContain('stackDepth');
    });

    it('errorText no longer compiles WebAssembly (a CSP wasm-eval violation on every run)', () => {
        const result = errorText();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        expect(result.value).not.toHaveProperty('wasmCompile');
        expect(Object.keys(result.value).length).toBeGreaterThan(10);
    });

    it('intl reports the zone offsets without the formatted date string that changed daily', () => {
        const result = intl();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        const timeZone = result.value.timeZone as Record<string, unknown>;
        expect(Object.keys(timeZone).sort()).toEqual(['januaryOffset', 'julyOffset', 'name', 'offset']);
    });

    it('permissions queries only registry names that need no extended descriptor', async () => {
        const asked: string[] = [];
        const undo = defineOwn(navigator, 'permissions', {
            query: async ({ name }: { name: string }) => {
                asked.push(name);
                if (name === 'camera') throw new TypeError('not a valid enumeration value');
                return { state: 'prompt' };
            },
        });
        try {
            const result = await permissions();
            expect(result.state).toBe('ok');
            if (result.state !== 'ok') return;

            for (const invalid of ['hid', 'gamepad', 'web-share', 'push', 'fullscreen', 'top-level-storage-access', 'pointer-lock', 'bluetooth']) {
                expect(asked).not.toContain(invalid);
            }
            expect(asked).toContain('geolocation');
            expect(asked).toHaveLength(18);
            expect(result.value.unsupported).toBe(1);
            expect(result.value.prompt).toBe(17);
        } finally {
            undo();
        }
    });

    it('environment records the identity fields a spoofer must fabricate', () => {
        const result = environment();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        const identity = result.value.identity as Record<string, unknown>;
        expect(identity).toHaveProperty('userAgent');
        expect(identity).toHaveProperty('webdriver');
        expect(identity).toHaveProperty('hardwareConcurrency');
    });

    it('audioRealtime degrades to an error rather than throwing under jsdom', () => {
        const result = audioRealtime();
        expect(['ok', 'unavailable', 'error']).toContain(result.state);
    });

    it('probes that need a browser report a state rather than returning garbage', () => {
        for (const run of [textMetrics, errorText, codecs]) {
            expect(['ok', 'unavailable', 'error']).toContain(run().state);
        }
    });
});

describe('hardware probes', () => {
    it('architecture reads the NaN sign byte and names a real architecture on this machine', () => {
        const result = architecture();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        expect(['x86', 'arm']).toContain(result.value.nanSign);
        expect(architecture()).toEqual(result);
    });

    describe('fontMetrics', () => {
        // Widths: generics have fixed widths; two named families are installed and
        // differ from every generic; every other family falls back to the generic's
        // width, which is how an absent font measures.
        const widthOf = (font: string, text: string): number => {
            const scale = text.length;
            if (font.includes('"Arial"')) return 7.2 * scale;
            if (font.includes('"Verdana"')) return 9.6 * scale;
            if (font.endsWith('sans-serif')) return 8 * scale;
            if (font.endsWith('serif')) return 8.5 * scale;
            return 6 * scale; // monospace
        };

        it('emits a sorted, de-duplicated pair list and a count, and no family names', () => {
            const undo = installFakeCanvas(widthOf);
            try {
                const result = fontMetrics();
                expect(result.state).toBe('ok');
                if (result.state !== 'ok') return;

                // Arial: T1 (21 chars) 151.2 → 151, T2 (41 chars) 295.2 → 295.
                // Verdana: 201.6 → 202, 393.6 → 394. Sorted as strings.
                expect(result.value).toEqual({ count: 2, pairs: '151:295,202:394' });
                expect(JSON.stringify(result.value)).not.toMatch(/Arial|Verdana/);
            } finally {
                undo();
            }
        });

        it('de-duplicates families that resolve to the same font', () => {
            const undo = installFakeCanvas((font, text) =>
                /"(Arial|Helvetica|Liberation Sans)"/.test(font) ? 7 * text.length : widthOf(font, text),
            );
            try {
                const result = fontMetrics();
                if (result.state !== 'ok') return;
                expect(result.value.count).toBe(4); // Arial, Helvetica, Liberation Sans, Verdana
                expect(result.value.pairs).toBe('147:287,202:394');
            } finally {
                undo();
            }
        });

        it('is deterministic across calls, and a font whose width equals one generic is still found through the others', () => {
            // A real font measures the same whatever the fallback is, so a family whose
            // width happens to equal sans-serif's is still caught by the serif comparison.
            const undo = installFakeCanvas((font, text) => (font.includes('"Roboto"') ? 8 * text.length : widthOf(font, text)));
            try {
                const first = fontMetrics();
                expect(canonicalise(first)).toBe(canonicalise(fontMetrics()));
                if (first.state === 'ok') {
                    expect(first.value.count).toBe(3);
                    expect(first.value.pairs).toBe('151:295,168:328,202:394');
                }
            } finally {
                undo();
            }
        });

        it('reports an error state without a 2D context rather than throwing', () => {
            expect(fontMetrics().state).toBe('error');
        });
    });

    it('emojiMetrics rounds the width of the fixed ZWJ string, shaped with the OS emoji fonts first', () => {
        const measured: string[] = [];
        const undo = installFakeCanvas((font, text) => {
            measured.push(text);
            return font === '32px "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif' ? 119.77 : 0;
        });
        try {
            expect(emojiMetrics()).toEqual(ok({ width: 120 }));
            expect(measured).toEqual([EMOJI_SAMPLE]);
        } finally {
            undo();
        }
    });

    it('the emoji sample uses only code points every OS emoji font this product meets has (round-2 BR2-12)', () => {
        const codePoints = [...EMOJI_SAMPLE].map((char) => char.codePointAt(0) as number);
        // 😀, 🏳️‍🌈 and 👨‍👩‍👧: three glyphs, joined by ZWJ and VS16 inside the sequences.
        expect(codePoints.map((cp) => cp.toString(16))).toEqual(['1f600', '1f3f3', 'fe0f', '200d', '1f308', '1f468', '200d', '1f469', '200d', '1f467']);
        // Nothing from Symbols and Pictographs Extended-A (U+1FA70..U+1FAFF, Emoji 12.0 and
        // later) — the block of 🫠 (U+1FAE0, Emoji 14.0), which older OS emoji fonts lack and
        // each engine then fills differently.
        expect(codePoints.some((cp) => cp >= 0x1fa70 && cp <= 0x1faff)).toBe(false);
    });

    it('scripts compares each sample against the .notdef box and emits one bit per script', () => {
        // Everything measures like the notdef box except Hangul (index 6) and CJK (index 8).
        const undo = installFakeCanvas((_font, text) => (text === '가' || text === '中' ? 48 : 30));
        try {
            const result = scripts();
            expect(result.state).toBe('ok');
            if (result.state !== 'ok') return;
            expect(result.value.bits).toBe('0000001010000000');
            expect(result.value.bits).toHaveLength(16);
        } finally {
            undo();
        }
    });

    it('gpu reports null for both APIs where neither exists, without throwing', async () => {
        const result = await gpu();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value).toEqual({ webgpu: null, webgl: null, mirroredParamsAgree: null });
    });

    it('normaliseRenderer strips wrappers, API names, driver versions and PCI ids', () => {
        expect(normaliseRenderer('ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 (0x00002206) Direct3D11 vs_5_0 ps_5_0, D3D11)')).toBe('nvidia nvidia geforce rtx 3080');
        expect(normaliseRenderer('NVIDIA GeForce RTX 3080/PCIe/SSE2')).toBe('nvidia geforce rtx 3080');
        expect(normaliseRenderer('Apple GPU')).toBe('apple gpu');
        expect(normaliseRenderer('Mesa Intel(R) UHD Graphics 620 (KBL GT2)')).toBe('mesa intel r uhd graphics 620 kbl gt2');
    });

    it('audioHardware reports an error state without an AudioContext', () => {
        expect(audioHardware().state).toBe('error');
    });

    it('decoders encodes supported/smooth/powerEfficient as three bits per codec', async () => {
        const undo = defineOwn(navigator, 'mediaCapabilities', {
            decodingInfo: async ({ video }: { video: { contentType: string } }) => {
                if (video.contentType.includes('av01')) throw new TypeError('unsupported configuration');
                return {
                    supported: true,
                    smooth: video.contentType.includes('avc1'),
                    powerEfficient: false,
                };
            },
        });
        try {
            expect(await decoders()).toEqual(ok({ h264: '110', vp9: '100', av1: 'err' }));
        } finally {
            undo();
        }
    });

    it('voices hashes the sorted OS voice names and excludes Chrome cloud voices', async () => {
        const list = [
            { name: 'Google US English', localService: false },
            { name: 'Microsoft Zira', localService: true },
            { name: 'Alex', localService: true },
        ];
        const undo = defineOwn(window, 'speechSynthesis', {
            getVoices: () => list,
            addEventListener: () => undefined,
        });
        try {
            expect(await voices()).toEqual(ok({ count: 3, osCount: 2, osHash: fnv1a32('Alex|Microsoft Zira') }));
        } finally {
            undo();
        }
    });

    it('voices is unavailable, not a value, when no voice ever arrives (round-2 BR2-4), and removes its listener', async () => {
        const listeners: string[] = [];
        const undo = defineOwn(window, 'speechSynthesis', {
            getVoices: () => [],
            addEventListener: (type: string) => listeners.push(`+${type}`),
            removeEventListener: (type: string) => listeners.push(`-${type}`),
        });
        try {
            const started = Date.now();
            expect(await voices()).toEqual({ state: 'unavailable', reason: 'timeout' });
            expect(Date.now() - started).toBeLessThan(2000);
            // The timer path removes the listener it added (round-2 PERF-22).
            expect(listeners).toEqual(['+voiceschanged', '-voiceschanged']);
        } finally {
            undo();
        }
    });

    it('voices is unavailable(empty) when the list arrives empty, and ok when voiceschanged brings voices', async () => {
        let handler: (() => void) | undefined;
        let list: Array<{ name: string }> = [];
        const undo = defineOwn(window, 'speechSynthesis', {
            getVoices: () => list,
            addEventListener: (_type: string, fn: () => void) => {
                handler = fn;
            },
            removeEventListener: () => undefined,
        });
        try {
            const pending = voices();
            list = [{ name: 'Alex' }];
            handler?.();
            expect(await pending).toEqual(ok({ count: 1, osCount: 1, osHash: fnv1a32('Alex') }));

            list = [];
            const pendingEmpty = voices();
            handler?.();
            expect(await pendingEmpty).toEqual({ state: 'unavailable', reason: 'empty' });
        } finally {
            undo();
        }
    });

    it('voices is unavailable without speechSynthesis', async () => {
        const undo = defineOwn(window, 'speechSynthesis', undefined);
        try {
            expect(await voices()).toEqual({ state: 'unavailable', reason: 'no-speech-synthesis' });
        } finally {
            undo();
        }
    });

    it('runTierChunked returns every probe of the tier as a tagged result, late probes last', async () => {
        const result = await runTierChunked(TIER.HARDWARE);
        expect(Object.keys(result)).toEqual(HARDWARE_PROBES);
        for (const value of Object.values(result)) {
            expect(['ok', 'unavailable', 'error']).toContain(value.state);
        }
    });

    it('audioRealtime and audioHardware carry no latency measurement (round-2 BR2-2)', async () => {
        const undo = defineOwn(window, 'AudioContext', class FakeAudioContext {
            sampleRate = 48000;
            baseLatency = 0.01;
            outputLatency = 0.032;
            destination = { maxChannelCount: 2, channelCount: 2, channelCountMode: 'explicit', channelInterpretation: 'speakers', numberOfInputs: 1, numberOfOutputs: 0 };
            close(): Promise<void> {
                return Promise.resolve();
            }
        });
        try {
            releaseShared();
            expect(audioRealtime()).toEqual(ok({
                sampleRate: 48000, maxChannelCount: 2, channelCount: 2, channelCountMode: 'explicit',
                channelInterpretation: 'speakers', numberOfInputs: 1, numberOfOutputs: 0,
            }));
            expect(audioHardware()).toEqual(ok({ sampleRate: 48000, maxChannelCount: 2 }));
            for (const result of [audioRealtime(), audioHardware()]) {
                expect(JSON.stringify(result)).not.toMatch(/[lL]atency/);
            }
        } finally {
            releaseShared();
            undo();
        }
    });

    it('permissions records the thrown error NAME for a rejected name (round-2 STD-7)', async () => {
        const undo = defineOwn(navigator, 'permissions', {
            query: ({ name }: { name: string }) => {
                if (name === 'midi') return Promise.reject(new DOMException('no', 'NotSupportedError'));
                if (name === 'geolocation') return Promise.resolve({ state: 'prompt' });
                return Promise.reject(new TypeError('unknown name'));
            },
        });
        try {
            const result = await permissions();
            expect(result.state).toBe('ok');
            if (result.state !== 'ok') return;
            const states = String(result.value.states).split(',');
            expect(states).toContain('midi=NotSupportedError');
            expect(states).toContain('geolocation=prompt');
            expect(states).toContain('camera=TypeError');
            expect(states).not.toContain('camera=unsupported');
            expect(result.value.prompt).toBe(1);
            expect(result.value.unsupported).toBe(states.length - 1);
        } finally {
            undo();
        }
    });

    it('gpu asks for the WebGPU adapter once per page and remembers a null answer (round-2 BR2-7)', async () => {
        let calls = 0;
        const undo = defineOwn(navigator, 'gpu', {
            requestAdapter: () => {
                calls++;
                return Promise.resolve(null);
            },
        });
        try {
            resetWebgpuAdapterForTests();
            expect(await webgpuAdapter()).toBeNull();
            expect(await webgpuAdapter()).toBeNull();
            await gpu();
            await gpu();
            expect(calls).toBe(1);
        } finally {
            resetWebgpuAdapterForTests();
            undo();
        }
    });

    it('gpu reads isFallbackAdapter from adapter.info first (round-2 STD-25)', async () => {
        const undo = defineOwn(navigator, 'gpu', {
            requestAdapter: () => Promise.resolve({ info: { vendor: 'v', architecture: 'a', device: 'd', description: '', isFallbackAdapter: true } }),
        });
        try {
            resetWebgpuAdapterForTests();
            const result = await gpu();
            expect(result.state).toBe('ok');
            if (result.state !== 'ok') return;
            expect((result.value.webgpu as Record<string, unknown>).fallback).toBe(true);
        } finally {
            resetWebgpuAdapterForTests();
            releaseShared();
            undo();
        }
    });
});

describe('fontMetrics as steps (decision D5)', () => {
    it('measures the same value whether run at once or step by step, over FONT_METRICS_STEPS steps', () => {
        const undo = installFakeCanvas((font, text) => {
            // Six families "exist": their width differs from the generic's.
            const present = ['Arial', 'Menlo', 'Roboto', 'DejaVu Sans', 'Consolas', 'Inter'].some((family) => font.includes(`"${family}"`));
            return (present ? 100 : 50) + text.length;
        });
        try {
            const atOnce = fontMetrics();
            const stepped = fontMetricsSteps();
            expect(stepped.steps).toHaveLength(FONT_METRICS_STEPS);
            for (const step of stepped.steps) step();
            expect(ok(stepped.result())).toEqual(atOnce);
            expect(atOnce.state).toBe('ok');
            if (atOnce.state === 'ok') expect(atOnce.value.count).toBe(6);
        } finally {
            undo();
        }
    });

    it('the steps together cover every family exactly once', () => {
        const chunks = fontMetricsChunks();
        expect(chunks).toHaveLength(FONT_METRICS_STEPS);
        const all = chunks.flat();
        expect(all).toHaveLength(FONT_METRICS_FAMILIES.length);
        expect(new Set(all)).toEqual(new Set(FONT_METRICS_FAMILIES));
        for (const chunk of chunks) expect(chunk.length).toBeGreaterThan(0);
    });

    it('deals every OS group out over the steps, so no step holds one OS’s families alone (round-3 CL3-5)', () => {
        const groups = {
            windows: FONT_METRICS_FAMILIES.slice(0, FONT_METRICS_FAMILIES.indexOf('American Typewriter')),
            mac: FONT_METRICS_FAMILIES.slice(FONT_METRICS_FAMILIES.indexOf('American Typewriter'), FONT_METRICS_FAMILIES.indexOf('Cantarell')),
            linux: FONT_METRICS_FAMILIES.slice(FONT_METRICS_FAMILIES.indexOf('Cantarell'), FONT_METRICS_FAMILIES.indexOf('Droid Sans')),
        };
        const chunks = fontMetricsChunks();
        for (const [os, families] of Object.entries(groups)) {
            const perStep = chunks.map((chunk) => chunk.filter((family) => families.includes(family)).length);
            // Within one family of an even share in every step.
            expect(Math.max(...perStep) - Math.min(...perStep), `${os}: ${perStep.join('/')}`).toBeLessThanOrEqual(1);
        }
    });

    it('the value does not depend on the chunking: equal to one pass over the families in list order', () => {
        // Present families get DISTINCT widths, so each contributes its own pair.
        const present = ['Arial', 'Calibri', 'Menlo', 'Helvetica Neue', 'Roboto', 'DejaVu Sans', 'DejaVu Sans Mono', 'Liberation Serif', 'Ubuntu', 'Inter'];
        const widthOf = (font: string, text: string): number => {
            const index = present.findIndex((family) => font.includes(`"${family}"`));
            return (index >= 0 ? 200 + index * 7 : 50) + text.length;
        };
        const undo = installFakeCanvas(widthOf);
        try {
            // The pre-CL3-5 algorithm, written out: every family in order, first differing generic.
            const T1 = 'mmmmmmmmmmlliI1O0WwQ@';
            const T2 = 'The quick brown fox jumps over 1234567890';
            const base = Object.fromEntries(['sans-serif', 'serif', 'monospace'].map((g) => [g, widthOf(`48px ${g}`, T1)]));
            const pairs = new Set<string>();
            let count = 0;
            for (const family of FONT_METRICS_FAMILIES) {
                for (const generic of ['sans-serif', 'serif', 'monospace']) {
                    const font = `48px "${family}", ${generic}`;
                    const w1 = widthOf(font, T1);
                    if (Math.abs(w1 - (base[generic] as number)) > 0.01) {
                        count++;
                        pairs.add(`${Math.round(w1)}:${Math.round(widthOf(font, T2))}`);
                        break;
                    }
                }
            }
            const reference = { count, pairs: [...pairs].sort().join(',') };
            expect(reference.count).toBe(present.length);

            expect(fontMetrics()).toEqual(ok(reference));
            const stepped = fontMetricsSteps();
            // Steps run in REVERSE order still give the same value: chunking and order are free.
            [...stepped.steps].reverse().forEach((step) => step());
            expect(stepped.result()).toEqual(reference);
        } finally {
            undo();
        }
    });
});

describe('scripts as steps (round-3 CL3-5)', () => {
    // Hangul (6), CJK (8) and Myanmar (15) find a glyph; everything else measures like .notdef.
    const widthOf = (_font: string, text: string): number => (text === '가' || text === '中' || text === 'က' ? 48 : 30);

    it('measures the same bits whether run at once or step by step, over SCRIPTS_STEPS steps', () => {
        const undo = installFakeCanvas(widthOf);
        try {
            const atOnce = scripts();
            expect(atOnce).toEqual(ok({ bits: '0000001010000001' }));
            const stepped = scriptsSteps();
            expect(stepped.steps).toHaveLength(SCRIPTS_STEPS);
            [...stepped.steps].reverse().forEach((step) => step());
            expect(stepped.result()).toEqual({ bits: '0000001010000001' });
        } finally {
            undo();
        }
    });

    it('every sample is measured by exactly one step, against the .notdef reference', () => {
        const measured: string[] = [];
        const undo = installFakeCanvas((font, text) => {
            measured.push(text);
            return widthOf(font, text);
        });
        try {
            const stepped = scriptsSteps();
            const perStep = stepped.steps.map((step) => {
                const before = measured.length;
                step();
                return measured.slice(before);
            });
            // The .notdef reference (U+0378) once, by the first step; then the samples.
            expect(perStep[0]?.[0]).toBe('\u0378');
            const samples = perStep.flat().filter((text) => text !== '\u0378');
            expect(samples.sort()).toEqual([...SCRIPT_SAMPLES].sort());
            expect(perStep.flat().filter((text) => text === '\u0378')).toHaveLength(1);
        } finally {
            undo();
        }
    });

    it('refuses to produce a value when a step did not run, rather than a short bit string', () => {
        const undo = installFakeCanvas(widthOf);
        try {
            const stepped = scriptsSteps();
            stepped.steps[0]?.();
            expect(() => stepped.result()).toThrow('a step did not run');
        } finally {
            undo();
        }
    });
});

describe('collect', () => {
    it('produces a claim set with the documented shape and the tier1 slot', async () => {
        const result = await collect(CHALLENGE, 'signin');

        expect(result.claims.v).toBe(3);
        expect(result.claims.v).toBe(FINGERPRINT_VERSION);
        expect(result.slot).toBe('tier1');
        expect(result.claims.purpose).toBe('signin');
        expect(result.claims).toHaveProperty('integrity');
        expect(result.claims).toHaveProperty('tier1');
        expect(result.claims).not.toHaveProperty('tier2');
        expect(result.claims).toHaveProperty('timing');
        expect(result.claims.tier1).toHaveProperty('architecture');
        expect(typeof result.digest).toBe('string');
        expect(result.digest).toHaveLength(64);
    });

    it('records timing coherently against the declared budget', async () => {
        const result = await collect(CHALLENGE, 'signin');

        expect(result.claims.timing.budgetMs).toBe(BUDGET_MS);
        expect(result.claims.timing.elapsedMs).toBeGreaterThanOrEqual(0);
        expect(typeof result.claims.timing.tier2Skipped).toBe('boolean');
    });

    it('runs integrity probes before anything deferrable', async () => {
        const result = await collect(CHALLENGE, 'signin');

        expect(result.claims.integrity).toBeDefined();
        expect(result.claims.integrity.findings).toBeDefined();
    });

    it('is deterministic for the same challenge and environment', async () => {
        const first = await collect(CHALLENGE, 'signin');
        const second = await collect(CHALLENGE, 'signin');

        const strip = (claims: unknown): string =>
            canonicalise(
                JSON.parse(
                    JSON.stringify(claims, (key, value) => (key === 'timing' || key === 'elapsedMs' ? undefined : value)),
                ),
            );

        expect(strip(first.claims)).toBe(strip(second.claims));
    });

    it('produces the same digest regardless of which token carried it', async () => {
        const a = await collect(CHALLENGE, 'signin');
        const b = await collect({ ...CHALLENGE, token: 'a-different-token' }, 'signin');

        // The digest is a function of the claims and nothing else.
        expect(a.digest).toBe(b.digest);
    });

    it('never throws, even with no usable environment', async () => {
        await expect(collect(CHALLENGE, 'signin')).resolves.toBeDefined();
    });

    it('sends an empty digest rather than rejecting where SubtleCrypto is absent', async () => {
        const undo = defineOwn(globalThis.crypto, 'subtle', undefined);
        try {
            const result = await collect(CHALLENGE, 'signin');
            expect(result.digest).toBe('');
            expect(Object.keys(result.claims.tier1).length).toBeGreaterThan(5);
        } finally {
            undo();
        }
    });
});

describe('collectTier2 and scheduleTier2', () => {
    it('merges the engine tier and the hardware tier into one tier2 block under the tier2 slot', async () => {
        const result = await collectTier2(CHALLENGE, 'signin');

        expect(result.slot).toBe('tier2');
        expect(result.claims.tier1).toEqual({});
        const names = Object.keys(result.claims.tier2 ?? {});
        for (const name of ['textMetrics', 'intl', 'audioOffline', ...HARDWARE_PROBES]) {
            expect(names).toContain(name);
        }
        // A probe that failed under jsdom travels as `{ state }`, never as a bare throw.
        const fontMetricsOnWire = (result.claims.tier2 as Record<string, unknown>).fontMetrics as Record<string, unknown>;
        expect(fontMetricsOnWire).toEqual({ state: 'error' });
    });

    it('scheduleTier2 resolves with the collected result instead of null', async () => {
        const seen: unknown[] = [];
        const result = await scheduleTier2(CHALLENGE, 'signin', (r) => seen.push(r));

        expect(result).not.toBeNull();
        expect(result?.slot).toBe('tier2');
        expect(seen).toHaveLength(1);
        expect(seen[0]).toBe(result);
    });
});

describe('envelope and transport', () => {
    it('carries the token, the slot and the digest, and no secret', async () => {
        const result = await collect(CHALLENGE, 'signin');
        const envelope = buildEnvelope({ challenge: CHALLENGE, slot: 'tier1', digest: result.digest, claims: result.claims });

        expect(envelope.v).toBe(3);
        expect(envelope.nonce).toBe(CHALLENGE.token);
        expect(envelope.slot).toBe('tier1');
        expect(envelope.digest).toBe(result.digest);
        expect('exp' in envelope).toBe(false);
        expect('sig' in envelope).toBe(false);
        expect(Object.keys(envelope).sort()).toEqual(['claims', 'digest', 'nonce', 'probes', 'slot', 'v']);
        expect(envelope.probes).toBe(PROBE_SET);
    });

    it('builds the decline body with the token and no claims', () => {
        expect(buildDecline(CHALLENGE, 'blocked')).toEqual({ v: 3, nonce: CHALLENGE.token, declined: true, reason: 'blocked' });
    });

    it('counts the payload in UTF-8 bytes against the 24 KiB server limit', () => {
        expect(TRANSPORT_LIMITS.maxPayloadBytes).toBe(24 * 1024);
        expect(payloadBytes('abc')).toBe(3);
        expect(payloadBytes('€')).toBe(3);
        expect(payloadBytes('😀')).toBe(4);
    });

    it('serialises both envelopes inside the server limit', async () => {
        const tier1 = await collect(CHALLENGE, 'signin');
        const tier2 = await collectTier2(CHALLENGE, 'signin');

        for (const result of [tier1, tier2]) {
            const json = JSON.stringify(buildEnvelope({ challenge: CHALLENGE, slot: result.slot, digest: result.digest, claims: result.claims }));
            expect(payloadBytes(json)).toBeLessThan(TRANSPORT_LIMITS.maxPayloadBytes);
        }
    });

    it('refuses to send an oversized envelope instead of letting the server drop it silently', async () => {
        const recorder = installRecordingFetch();
        try {
            const result = await collect(CHALLENGE, 'signin');
            const padded = { ...result.claims, tier1: { ...result.claims.tier1, pad: '€'.repeat(6000) } };
            const sent = sendClaims('/claims', { challenge: CHALLENGE, slot: 'tier1', digest: result.digest, claims: padded });

            expect(sent).toMatchObject({ sent: false, reason: 'oversize' });
            expect(recorder.calls).toHaveLength(0);
        } finally {
            recorder.undo();
        }
    });
});

describe('send results (nothing is dropped silently)', () => {
    it('sendClaims reports no-fetch when the engine has no fetch', async () => {
        const original = globalThis.fetch;
        (globalThis as { fetch?: unknown }).fetch = undefined;
        try {
            const result = await collect(CHALLENGE, 'signin');
            const out = sendClaims('/claims', { challenge: CHALLENGE, slot: 'tier1', digest: result.digest, claims: result.claims });
            expect(out).toMatchObject({ sent: false, reason: 'no-fetch' });
            await expect(out.delivered).resolves.toBe(false);
        } finally {
            globalThis.fetch = original;
        }
    });

    it('sendClaims reports the oversize byte count, and a started request reports its bytes', async () => {
        const recorder = installRecordingFetch();
        try {
            const result = await collect(CHALLENGE, 'signin');
            const padded = { ...result.claims, tier1: { ...result.claims.tier1, pad: 'x'.repeat(TRANSPORT_LIMITS.maxPayloadBytes) } };
            const big = sendClaims('/claims', { challenge: CHALLENGE, slot: 'tier1', digest: result.digest, claims: padded });
            expect(big.sent).toBe(false);
            expect(big.sent === false && big.reason).toBe('oversize');
            expect(big.sent === false && (big.bytes ?? 0)).toBeGreaterThan(TRANSPORT_LIMITS.maxPayloadBytes);

            const ok = sendClaims('/claims', { challenge: CHALLENGE, slot: 'tier1', digest: result.digest, claims: result.claims });
            expect(ok.sent).toBe(true);
            expect(ok.sent && ok.bytes).toBeGreaterThan(100);
            expect(recorder.calls).toHaveLength(1);
        } finally {
            recorder.undo();
        }
    });

    it('sendClaims returns the cause when serialisation throws, instead of swallowing it', async () => {
        const recorder = installRecordingFetch();
        try {
            const result = await collect(CHALLENGE, 'signin');
            const cyclic: Record<string, unknown> = {};
            cyclic.self = cyclic;
            const out = sendClaims('/claims', {
                challenge: CHALLENGE,
                slot: 'tier1',
                digest: result.digest,
                claims: { ...result.claims, tier1: cyclic },
            });
            expect(out.sent).toBe(false);
            expect(out.sent === false && out.reason).toBe('threw');
            expect(out.sent === false && out.error).toBeInstanceOf(TypeError);
            expect(recorder.calls).toHaveLength(0);
        } finally {
            recorder.undo();
        }
    });

    it('requestChallenge names the cause: http status, malformed body, network error', async () => {
        const original = globalThis.fetch;
        try {
            globalThis.fetch = (async () => new Response('', { status: 503 })) as typeof fetch;
            expect(await requestChallenge('/challenge', 'signin')).toEqual({ challenge: null, reason: 'http', status: 503 });

            globalThis.fetch = (async () => new Response('{"token":""}', { status: 200 })) as typeof fetch;
            expect(await requestChallenge('/challenge', 'signin')).toEqual({ challenge: null, reason: 'malformed' });

            const boom = new TypeError('offline');
            globalThis.fetch = (async () => {
                throw boom;
            }) as typeof fetch;
            expect(await requestChallenge('/challenge', 'signin')).toEqual({ challenge: null, reason: 'network', error: boom });
        } finally {
            globalThis.fetch = original;
        }
    });
});

describe('collectAndSendDetailed', () => {
    it('reports sent, with the tier-1 send and a tier2 promise that settles with its own send', async () => {
        const recorder = installRecordingFetch('issued-token');
        try {
            const outcome = await collectAndSendDetailed('signin', '/challenge', '/claims');
            expect(outcome.status).toBe('sent');
            if (outcome.status !== 'sent') return;
            expect(outcome.send.sent).toBe(true);
            expect(outcome.result.slot).toBe('tier1');

            const tier2 = await outcome.tier2;
            expect(tier2.result?.slot).toBe('tier2');
            expect(tier2.send?.sent).toBe(true);
        } finally {
            recorder.undo();
        }
    });

    it('reports no-challenge with the cause, and the wrapper answers null', async () => {
        const original = globalThis.fetch;
        globalThis.fetch = (async () => new Response('', { status: 429 })) as typeof fetch;
        try {
            expect(await collectAndSendDetailed('signin', '/challenge', '/claims')).toEqual({
                status: 'no-challenge',
                challenge: { challenge: null, reason: 'http', status: 429 },
            });
            expect(await collectAndSend('signin', '/challenge', '/claims')).toBeNull();
        } finally {
            globalThis.fetch = original;
        }
    });

    it('reports send-failed (and sends no tier 2) when tier 1 is over the limit; the wrapper answers null', async () => {
        const recorder = installRecordingFetch('issued-token');
        const original = JSON.stringify;
        // Make only the claims body oversized; the challenge request body stays small.
        const spy = vi.spyOn(JSON, 'stringify').mockImplementation((value: unknown, ...rest: unknown[]) => {
            const json = (original as (...a: unknown[]) => string)(value, ...rest);
            return (value as { slot?: string } | null)?.slot === 'tier1' ? json + ' '.repeat(TRANSPORT_LIMITS.maxPayloadBytes) : json;
        });
        try {
            const outcome = await collectAndSendDetailed('signin', '/challenge', '/claims');
            expect(outcome.status).toBe('send-failed');
            expect(outcome.status === 'send-failed' && outcome.send).toMatchObject({ sent: false, reason: 'oversize' });
            expect(await collectAndSend('signin', '/challenge', '/claims')).toBeNull();
            expect(recorder.calls.filter((c) => c.url === '/claims')).toHaveLength(0);
        } finally {
            spy.mockRestore();
            recorder.undo();
        }
    });

    it('reports collect-failed with the decline that spent the token', async () => {
        const recorder = installRecordingFetch('issued-token');
        const spy = vi.spyOn(performance, 'now').mockImplementation(() => {
            throw new DOMException('collection is blocked', 'SecurityError');
        });
        try {
            const outcome = await collectAndSendDetailed('signin', '/challenge', '/claims');
            expect(outcome.status).toBe('collect-failed');
            if (outcome.status !== 'collect-failed') return;
            expect(outcome.reason).toBe('blocked');
            expect(outcome.declined.sent).toBe(true);
            expect(outcome.error).toBeInstanceOf(DOMException);
        } finally {
            spy.mockRestore();
            recorder.undo();
        }
    });
});

describe('collectAndSend', () => {
    it('posts the tier1 envelope immediately and the tier2 envelope later, under the same nonce', async () => {
        const recorder = installRecordingFetch('issued-token');
        try {
            const result = await collectAndSend('signin', '/challenge', '/claims');
            expect(result).not.toBeNull();
            expect(result?.slot).toBe('tier1');

            // The deferred send is scheduled through setTimeout under jsdom (no
            // requestIdleCallback) and takes a few hundred ms including the voices wait.
            await vi.waitFor(() => expect(recorder.calls.filter((c) => c.url === '/claims')).toHaveLength(2), { timeout: 5000 });

            const [challenge, first, second] = recorder.calls;
            expect(challenge?.url).toBe('/challenge');
            expect(challenge?.body).toEqual({ purpose: 'signin' });
            const tier1 = first?.body as Record<string, unknown>;
            const tier2 = second?.body as Record<string, unknown>;
            expect(tier1.v).toBe(3);
            expect(tier1.slot).toBe('tier1');
            expect(tier2.slot).toBe('tier2');
            expect(tier1.nonce).toBe('issued-token');
            expect(tier2.nonce).toBe('issued-token');
            expect((tier2.claims as Record<string, unknown>).tier2).toHaveProperty('fontMetrics');
        } finally {
            recorder.undo();
        }
    });

    it('spends the token on a decline when collect() itself fails', async () => {
        const recorder = installRecordingFetch('issued-token');
        const spy = vi.spyOn(performance, 'now').mockImplementation(() => {
            throw new DOMException('collection is blocked', 'SecurityError');
        });
        try {
            const result = await collectAndSend('signin', '/challenge', '/claims');
            expect(result).toBeNull();

            await vi.waitFor(() => expect(recorder.calls).toHaveLength(2));
            expect(recorder.calls[1]?.url).toBe('/claims');
            expect(recorder.calls[1]?.body).toEqual({ v: 3, nonce: 'issued-token', declined: true, reason: 'blocked' });
        } finally {
            spy.mockRestore();
            recorder.undo();
        }
    });

    it('returns null and sends nothing when no challenge is issued', async () => {
        const original = globalThis.fetch;
        const calls: string[] = [];
        globalThis.fetch = (async (input: RequestInfo | URL) => {
            calls.push(String(input));
            return new Response('', { status: 503 });
        }) as typeof fetch;
        try {
            expect(await collectAndSend('signin', '/challenge', '/claims')).toBeNull();
            expect(calls).toEqual(['/challenge']);
        } finally {
            globalThis.fetch = original;
        }
    });
});

describe('hashing', () => {
    it('sha256Hex matches the known digest of the empty string', async () => {
        expect(await sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('claimDigest is a pure function of the claims', async () => {
        expect(await claimDigest({ b: 2, a: 1 })).toBe(await claimDigest({ a: 1, b: 2 }));
    });

    it('claimDigest still distinguishes genuinely different claims', async () => {
        expect(await claimDigest({ a: 1 })).not.toBe(await claimDigest({ a: 2 }));
        expect(await claimDigest({ a: 1 })).not.toBe(await claimDigest({ a: '1' }));
    });
});

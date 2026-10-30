/**
 * The CONTRACT-2 value probes: `timezoneLmt` (V2), `fontFaces` (V3), `gpu.mirroredParamsAgree`
 * (V4), `parallelism` (V5) and `keyboardLayout` (V6).
 *
 * jsdom has none of the APIs these read, so each test installs a fake that really computes
 * (a WebGL fake that answers `getParameter`, workers whose loop counts follow a core model, a
 * font set with a fixed installed list). The real engines are covered by
 * tests/Browser/transport-checks.mjs (check h), where these probes were also measured.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { fnv1a32 } from '@device-id/v3/canonical';
import { releaseShared } from '@device-id/v3/shared';
import { collectTier2 } from '@device-id/v3/index';
import {
    FONT_FACE_FAMILIES,
    FONT_FACES_TIMEOUT_MS,
    KEYBOARD_CODES,
    KEYBOARD_LAYOUT_TIMEOUT_MS,
    PARALLELISM_TIMEOUT_MS,
    parallelCapacity,
    fontFaces,
    gpu,
    keyboardLayout,
    parallelism,
    parallelismBucket,
    probesOf,
    timezoneLmt,
    TIER,
} from '@device-id/v3/value-probes';

const undos: Array<() => void> = [];
afterEach(() => {
    vi.unstubAllEnvs();
    vi.useRealTimers();
    while (undos.length) undos.pop()?.();
    releaseShared();
});

function defineOwn(target: object, name: string, value: unknown): void {
    const original = Object.getOwnPropertyDescriptor(target, name);
    Object.defineProperty(target, name, { value, configurable: true, writable: true });
    undos.push(() => {
        if (original) Object.defineProperty(target, name, original);
        else delete (target as Record<string, unknown>)[name];
    });
}

describe('registry placement', () => {
    it('puts timezoneLmt in tier 2 after intl, and the hardware additions last, before the late audio probe (decision D5)', () => {
        const two = probesOf(TIER.TWO).map((p) => p.name);
        expect(two.indexOf('timezoneLmt')).toBe(two.indexOf('intl') + 1);
        // `audioHardware` is scheduled after everything (`late`), so it closes the registry.
        expect(probesOf(TIER.HARDWARE).map((p) => p.name).slice(-4)).toEqual(['fontFaces', 'keyboardLayout', 'parallelism', 'audioHardware']);
    });
});

// ---------------------------------------------------------------------------
// V2 timezoneLmt
// ---------------------------------------------------------------------------

describe('timezoneLmt', () => {
    it('sends ONLY the verdict, and agrees in an honest environment', () => {
        const result = timezoneLmt();
        expect(result).toEqual({ state: 'ok', value: { agree: true } });
    });

    it('DISAGREES when only Intl claims another zone — and the real zone\'s offset is not sent', () => {
        const original = Intl.DateTimeFormat.prototype.resolvedOptions;
        const spoofed = function (this: Intl.DateTimeFormat): Intl.ResolvedDateTimeFormatOptions {
            return { ...original.call(this), timeZone: 'Asia/Kolkata' };
        };
        defineOwn(Intl.DateTimeFormat.prototype, 'resolvedOptions', spoofed);

        const result = timezoneLmt();
        expect(result).toEqual({ state: 'ok', value: { agree: false } });
        // Privacy (five-review round): neither 1113 offset travels.
        expect(JSON.stringify(result)).not.toMatch(/Offset|353|\d{2,}/);
    });

    it('reports agree null when Intl cannot format, without failing the probe', () => {
        defineOwn(Intl.DateTimeFormat.prototype, 'formatToParts', () => {
            throw new RangeError('no');
        });

        expect(timezoneLmt()).toEqual({ state: 'ok', value: { agree: null } });
    });
});

// ---------------------------------------------------------------------------
// V3 fontFaces
// ---------------------------------------------------------------------------

const ALL_FAMILIES = Object.values(FONT_FACE_FAMILIES).flat();

/**
 * A FontFace whose `load()` fulfils only for families in `installed`, and records every
 * face it was asked for, as `local()` loading behaves in the three engines.
 */
function installFontFace(installed: (family: string) => boolean | 'throw' | 'hang'): { asked: Array<{ family: string; source: string }> } {
    const asked: Array<{ family: string; source: string }> = [];
    class FakeFontFace {
        constructor(readonly family: string, readonly source: string) {
            asked.push({ family, source });
        }
        load(): Promise<this> {
            const answer = installed(this.family);
            if (answer === 'throw') throw new TypeError('load threw synchronously');
            if (answer === 'hang') return new Promise(() => undefined);
            return answer ? Promise.resolve(this) : Promise.reject(new DOMException('A network error occurred.', 'NetworkError'));
        }
    }
    defineOwn(globalThis, 'FontFace', FakeFontFace);
    return { asked };
}

describe('fontFaces', () => {
    it('is unavailable (no-font-loading) under jsdom, which has no FontFace', async () => {
        expect(typeof (globalThis as { FontFace?: unknown }).FontFace).toBe('undefined');
        await expect(fontFaces()).resolves.toEqual({ state: 'unavailable', reason: 'no-font-loading' });
    });

    it('is unavailable (check-dishonest) when a face for a family that cannot exist loads', async () => {
        installFontFace(() => true);
        await expect(fontFaces()).resolves.toEqual({ state: 'unavailable', reason: 'check-dishonest' });
    });

    it('loads every family through local() and reports only the total and per-OS counts', async () => {
        const installed = new Set(['Segoe UI', 'Calibri', 'DejaVu Sans', 'Liberation Sans', 'Noto Color Emoji', 'Roboto', 'Google Sans']);
        const fake = installFontFace((family) => installed.has(family));

        const result = await fontFaces();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        expect(fake.asked[0]).toEqual({ family: 'nc-no-such-font-7f3a', source: 'local("nc-no-such-font-7f3a")' });
        expect(fake.asked.slice(1)).toEqual(ALL_FAMILIES.map((family) => ({ family, source: `local("${family}")` })));
        // No per-family bits any more (five-review round): the exact installed set is not sent.
        expect(result.value).toEqual({ count: 7, windows: 2, mac: 0, linux: 3, android: 1 });
        expect(JSON.stringify(result.value)).not.toMatch(/Segoe|DejaVu|Roboto/);
    });

    it('counts a family whose load throws synchronously as absent, without failing the probe', async () => {
        installFontFace((family) => (family === 'Calibri' ? 'throw' : family === 'Tahoma'));

        const result = await fontFaces();
        expect(result.state === 'ok' && result.value.windows).toBe(1);
    });

    it('settles as unavailable (timeout) when a load never settles', async () => {
        vi.useFakeTimers();
        installFontFace((family) => (family === 'Menlo' ? 'hang' : false));

        const pending = fontFaces();
        await vi.advanceTimersByTimeAsync(FONT_FACES_TIMEOUT_MS);
        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'timeout' });
    });
});

// ---------------------------------------------------------------------------
// V6 keyboardLayout
// ---------------------------------------------------------------------------

const QWERTY: Record<string, string> = { KeyQ: 'q', KeyW: 'w', KeyE: 'e', KeyA: 'a', KeyZ: 'z', KeyY: 'y', KeyM: 'm', Semicolon: ';', Quote: "'", Backquote: '`', BracketLeft: '[', Minus: '-', Equal: '=', Slash: '/', Backslash: '\\', Digit2: '2', Digit3: '3' };
const AZERTY: Record<string, string> = { ...QWERTY, KeyQ: 'a', KeyW: 'z', KeyA: 'q', KeyZ: 'w', KeyM: ',', Semicolon: 'm', Digit2: 'é', Digit3: '"' };

function installKeyboard(getLayoutMap: () => Promise<ReadonlyMap<string, string>>): void {
    defineOwn(navigator, 'keyboard', { getLayoutMap });
}

describe('keyboardLayout', () => {
    it('is unavailable (no-keyboard-api) without navigator.keyboard (jsdom, Firefox, Safari)', async () => {
        await expect(keyboardLayout()).resolves.toEqual({ state: 'unavailable', reason: 'no-keyboard-api' });
    });

    it('hashes the 17 key values in the fixed order, and tells QWERTY from AZERTY', async () => {
        installKeyboard(async () => new Map(Object.entries({ ...QWERTY, KeyX: 'x' })));
        const qwerty = await keyboardLayout();
        undos.pop()?.();
        installKeyboard(async () => new Map(Object.entries(AZERTY)));
        const azerty = await keyboardLayout();

        expect(qwerty).toEqual({ state: 'ok', value: { hash: fnv1a32(KEYBOARD_CODES.map((code) => QWERTY[code]).join(',')), size: 18 } });
        expect(azerty.state === 'ok' && qwerty.state === 'ok' && azerty.value.hash !== qwerty.value.hash).toBe(true);
    });

    it('counts a missing key as the empty string (the headless Chromium empty map)', async () => {
        installKeyboard(async () => new Map());
        await expect(keyboardLayout()).resolves.toEqual({ state: 'ok', value: { hash: fnv1a32(KEYBOARD_CODES.map(() => '').join(',')), size: 0 } });
    });

    it('is an error when getLayoutMap rejects, and calls it on navigator.keyboard', async () => {
        const receivers: unknown[] = [];
        installKeyboard(function (this: unknown) {
            receivers.push(this);
            return Promise.reject(new TypeError('not allowed in this frame'));
        });

        await expect(keyboardLayout()).resolves.toEqual({ state: 'error', name: 'TypeError' });
        expect(receivers).toEqual([(navigator as { keyboard?: unknown }).keyboard]);
    });

    it('settles as unavailable (timeout) when getLayoutMap never resolves', async () => {
        vi.useFakeTimers();
        installKeyboard(() => new Promise(() => undefined));

        const pending = keyboardLayout();
        await vi.advanceTimersByTimeAsync(KEYBOARD_LAYOUT_TIMEOUT_MS);
        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'timeout' });
    });
});

// ---------------------------------------------------------------------------
// V4 gpu.mirroredParamsAgree
// ---------------------------------------------------------------------------

const GL = {
    VENDOR: 0x1f00, RENDERER: 0x1f01, MAX_TEXTURE_SIZE: 0x0d33, MAX_RENDERBUFFER_SIZE: 0x84e8, MAX_VERTEX_ATTRIBS: 0x8869,
    MAX_VARYING_VECTORS: 0x8dfc, MAX_COMBINED_TEXTURE_IMAGE_UNITS: 0x8b4d, ALIASED_POINT_SIZE_RANGE: 0x846d,
    MAX_VERTEX_UNIFORM_VECTORS: 0x8dfb, MAX_FRAGMENT_UNIFORM_VECTORS: 0x8dfd, MAX_TEXTURE_IMAGE_UNITS: 0x8872,
    FRAGMENT_SHADER: 0x8b30, VERTEX_SHADER: 0x8b31, HIGH_FLOAT: 0x8df2,
};
const UNMASKED = { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 };

interface FakeGlOptions {
    webgl2?: boolean;
    /** Override one context type's answer for one parameter (a one-sided spoof). */
    patch?: { kind: 'webgl' | 'webgl2'; pname: number; value: unknown };
}

function installFakeWebGl({ webgl2 = true, patch }: FakeGlOptions = {}): { lost: string[] } {
    const lost: string[] = [];
    const base: Record<number, unknown> = {
        [GL.MAX_TEXTURE_SIZE]: 8192, [GL.MAX_RENDERBUFFER_SIZE]: 8192, [GL.MAX_VERTEX_ATTRIBS]: 16, [GL.MAX_VARYING_VECTORS]: 31,
        [GL.MAX_COMBINED_TEXTURE_IMAGE_UNITS]: 64, [GL.ALIASED_POINT_SIZE_RANGE]: new Float32Array([1, 1023]),
        [GL.MAX_VERTEX_UNIFORM_VECTORS]: 4096, [GL.MAX_FRAGMENT_UNIFORM_VECTORS]: 1024, [GL.MAX_TEXTURE_IMAGE_UNITS]: 32,
        [UNMASKED.UNMASKED_VENDOR_WEBGL]: 'Fake Vendor', [UNMASKED.UNMASKED_RENDERER_WEBGL]: 'Fake GPU 9000',
        [GL.VENDOR]: 'WebKit', [GL.RENDERER]: 'WebKit WebGL',
    };
    const make = (kind: 'webgl' | 'webgl2'): unknown => ({
        ...GL,
        getParameter: (pname: number) => (patch && patch.kind === kind && patch.pname === pname ? patch.value : base[pname]),
        getExtension: (name: string) =>
            name === 'WEBGL_debug_renderer_info' ? UNMASKED : name === 'WEBGL_lose_context' ? { loseContext: () => lost.push(kind) } : null,
        getShaderPrecisionFormat: () => ({ rangeMin: 127, rangeMax: 127, precision: 23 }),
        getSupportedExtensions: () => [],
    });

    const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
    const original = proto.getContext;
    proto.getContext = (kind: string): unknown => (kind === 'webgl' || (kind === 'webgl2' && webgl2) ? make(kind as 'webgl' | 'webgl2') : null);
    undos.push(() => {
        proto.getContext = original;
    });
    defineOwn(globalThis, 'WebGL2RenderingContext', function WebGL2RenderingContext() {});
    releaseShared();

    return { lost };
}

describe('gpu.mirroredParamsAgree', () => {
    it('is null under jsdom (no WebGL at all)', async () => {
        const result = await gpu();
        expect(result.state === 'ok' && result.value.mirroredParamsAgree).toBeNull();
    });

    it('is true when WebGL 1 and WebGL 2 report the same limits and renderer, and loses the extra context', async () => {
        const fake = installFakeWebGl();

        const result = await gpu();
        expect(result.state === 'ok' && result.value.mirroredParamsAgree).toBe(true);
        // The shared context is WebGL 2; the WebGL 1 one was created for the comparison and lost.
        expect(fake.lost).toEqual(['webgl']);
    });

    it('is FALSE when getParameter is patched on one context type only', async () => {
        installFakeWebGl({ patch: { kind: 'webgl', pname: GL.MAX_TEXTURE_SIZE, value: 16384 } });
        const result = await gpu();
        expect(result.state === 'ok' && result.value.mirroredParamsAgree).toBe(false);
    });

    it('compares array parameters by value and the unmasked renderer too', async () => {
        installFakeWebGl({ patch: { kind: 'webgl2', pname: GL.ALIASED_POINT_SIZE_RANGE, value: new Float32Array([1, 1024]) } });
        expect(((await gpu()) as { value: { mirroredParamsAgree: unknown } }).value.mirroredParamsAgree).toBe(false);
        undos.splice(0).reverse().forEach((undo) => undo());

        installFakeWebGl({ patch: { kind: 'webgl', pname: UNMASKED.UNMASKED_RENDERER_WEBGL, value: 'NVIDIA GeForce RTX 4090' } });
        expect(((await gpu()) as { value: { mirroredParamsAgree: unknown } }).value.mirroredParamsAgree).toBe(false);
    });

    it('is null when the other version cannot be created — absence is not a disagreement', async () => {
        installFakeWebGl({ webgl2: false });
        const result = await gpu();
        expect(result.state === 'ok' && result.value.mirroredParamsAgree).toBeNull();
        expect(result.state === 'ok' && (result.value.webgl as { webgl2: boolean }).webgl2).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// V5 parallelism
// ---------------------------------------------------------------------------

type SpinReply = (worker: SpinWorker, ms: number, concurrent: number, burst: number) => unknown;

/**
 * A worker whose work count follows a `cores` model. Spin requests posted in the same tick
 * form one burst; each of the `concurrent` workers of a burst gets min(1, cores/concurrent)
 * of a core. `burst` counts bursts (0 = the warm-up).
 */
class SpinWorker extends EventTarget {
    static all: SpinWorker[] = [];
    static log: number[] = [];
    static cores = 4;
    static bursts = 0;
    static pending: Array<{ worker: SpinWorker; ms: number }> = [];
    static reply: SpinReply = (_worker, ms, concurrent) => ({
        kind: 'nc-spin',
        iterations: Math.round(ms * 25_000 * Math.min(1, SpinWorker.cores / concurrent)),
    });

    readonly url: string;
    readonly options: unknown;
    terminated = false;

    constructor(url: URL | string, options?: unknown) {
        super();
        this.url = String(url);
        this.options = options;
        SpinWorker.all.push(this);
    }

    postMessage(message: { ask?: string; ms?: number }): void {
        SpinWorker.log.push(message.ms ?? -1);
        if (SpinWorker.pending.length === 0) {
            queueMicrotask(() => {
                const burst = SpinWorker.pending.splice(0);
                const index = SpinWorker.bursts++;
                for (const { worker, ms } of burst) {
                    if (worker.terminated) continue;
                    const data = SpinWorker.reply(worker, ms, burst.length, index);
                    if (data !== undefined) worker.dispatchEvent(new MessageEvent('message', { data }));
                }
            });
        }
        SpinWorker.pending.push({ worker: this, ms: message.ms ?? 0 });
    }

    terminate(): void {
        this.terminated = true;
    }
}

function installSpinWorkers(cores: number, reply?: SpinReply): void {
    SpinWorker.all = [];
    SpinWorker.log = [];
    SpinWorker.pending = [];
    SpinWorker.bursts = 0;
    SpinWorker.cores = cores;
    const original = SpinWorker.reply;
    if (reply) SpinWorker.reply = reply;
    defineOwn(globalThis, 'Worker', SpinWorker);
    undos.push(() => {
        SpinWorker.reply = original;
    });
}

describe('parallelism', () => {
    it('is unavailable (no-worker) under jsdom', async () => {
        await expect(parallelism()).resolves.toEqual({ state: 'unavailable', reason: 'no-worker' });
    });

    for (const [cores, bucket] of [[1, '1-2'], [2, '1-2'], [3, '3-4'], [4, '3-4'], [6, '5-8'], [8, '5-8'], [16, '5-8']] as const) {
        it(`measures ${cores} usable core(s) as '${bucket}'`, async () => {
            installSpinWorkers(cores);
            const result = await parallelism();
            expect(result.state === 'ok' && result.value.bucket).toBe(bucket);
        });
    }

    it('starts eight same-origin module workers ONCE, warms all up, then runs rounds of 1, 2, 4, 8 on them, twice', async () => {
        installSpinWorkers(4);
        await parallelism();

        expect(SpinWorker.all).toHaveLength(8);
        expect(SpinWorker.all.every((worker) => worker.terminated)).toBe(true);
        expect(SpinWorker.all.every((worker) => /scope\.worker/.test(worker.url) && !/^(blob|data):/.test(worker.url))).toBe(true);
        expect(SpinWorker.all[0]?.options).toEqual({ type: 'module' });
        const pass = [40, ...Array<number>(2).fill(40), ...Array<number>(4).fill(40), ...Array<number>(8).fill(40)];
        expect(SpinWorker.log).toEqual([...Array<number>(8).fill(20), ...pass, ...pass]);
    });

    it('starts CLASSIC workers in a production build (no module workers in Firefox 111-113)', async () => {
        vi.stubEnv('DEV', false);
        installSpinWorkers(4);
        await parallelism();

        expect(SpinWorker.all).toHaveLength(8);
        expect(SpinWorker.all.every((worker) => worker.options === undefined)).toBe(true);
    });

    it('takes the BEST round, not the last: an 8-worker collapse does not lower the bucket', async () => {
        // 4 cores, but with 8 concurrent workers each gets only 0.2 of a core.
        installSpinWorkers(4, (_worker, ms, concurrent) => ({
            kind: 'nc-spin',
            iterations: Math.round(ms * 25_000 * (concurrent > 4 ? 0.2 : 1)),
        }));

        const result = await parallelism();
        expect(result.state === 'ok' && result.value.bucket).toBe('3-4');
    });

    it('keeps the best of the two passes: a load that slows the whole first pass does not lower the bucket', async () => {
        // Bursts 1-4 are the first pass (burst 0 is the warm-up); a busy machine gives every
        // worker of that pass only 0.3 of a core.
        installSpinWorkers(4, (_worker, ms, concurrent, burst) => ({
            kind: 'nc-spin',
            iterations: Math.round(ms * 25_000 * Math.min(1, 4 / concurrent) * (burst >= 1 && burst <= 4 ? 0.3 : 1)),
        }));

        const result = await parallelism();
        expect(result.state === 'ok' && result.value.bucket).toBe('3-4');
    });

    it('does not let one slow (cold) round inflate the reading: one core is the fastest single worker', async () => {
        // The one-worker round (burst 1, after the warm-up burst 0) runs at half speed. Dividing
        // by that round would read 4 cores as 8.
        installSpinWorkers(4, (_worker, ms, concurrent, burst) => ({
            kind: 'nc-spin',
            iterations: Math.round(ms * 25_000 * Math.min(1, 4 / concurrent) * (burst === 1 ? 0.5 : 1)),
        }));

        const result = await parallelism();
        expect(result.state === 'ok' && result.value).toEqual({ bucket: '3-4', elapsedMs: expect.objectContaining({ capacity: 4 }) });
    });

    it('puts only the bucket in the claim; the round times and the raw capacity go under elapsedMs', async () => {
        installSpinWorkers(4);
        const result = await parallelism();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;

        expect(Object.keys(result.value)).toEqual(['bucket', 'elapsedMs']);
        expect(Object.keys(result.value.elapsedMs)).toEqual(['t1', 't2', 't4', 't8', 'capacity']);
        for (const ms of Object.values(result.value.elapsedMs)) expect(typeof ms).toBe('number');
        expect(result.value.elapsedMs.capacity).toBe(4);
    });

    it('parallelCapacity divides by the most work any single worker did, and is null with no work', () => {
        expect(parallelCapacity([
            { wallMs: 40, iterations: [500] },
            { wallMs: 40, iterations: [1000, 1000] },
            { wallMs: 40, iterations: [1000, 1000, 1000, 1000] },
            { wallMs: 40, iterations: Array<number>(8).fill(500) },
        ])).toBe(4);
        expect(parallelCapacity([{ wallMs: 40, iterations: [0] }])).toBeNull();
        expect(parallelCapacity([])).toBeNull();
    });

    it('is unavailable (malformed) on a reply that is not a spin reply, and terminates every worker', async () => {
        installSpinWorkers(4, () => ({ kind: 'nc-scope', snapshot: {} }));
        await expect(parallelism()).resolves.toEqual({ state: 'unavailable', reason: 'malformed' });
        expect(SpinWorker.all.every((worker) => worker.terminated)).toBe(true);
    });

    it('is unavailable (unmeasurable) when no worker does any work', async () => {
        installSpinWorkers(4, () => ({ kind: 'nc-spin', iterations: 0 }));
        await expect(parallelism()).resolves.toEqual({ state: 'unavailable', reason: 'unmeasurable' });
    });

    it('is unavailable (timeout) when the session never finishes, and terminates its workers', async () => {
        vi.useFakeTimers();
        installSpinWorkers(4, (_worker, ms) => (ms === 20 ? { kind: 'nc-spin', iterations: 1 } : undefined));

        const pending = parallelism();
        await vi.advanceTimersByTimeAsync(PARALLELISM_TIMEOUT_MS);
        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'timeout' });
        expect(SpinWorker.all.every((worker) => worker.terminated)).toBe(true);
    });

    it('is settled (released) and its workers terminated by releaseShared()', async () => {
        installSpinWorkers(4, () => undefined);

        const pending = parallelism();
        await Promise.resolve();
        releaseShared();
        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'released' });
        expect(SpinWorker.all.every((worker) => worker.terminated)).toBe(true);
    });

    it('is unavailable (blocked) when the constructor throws', async () => {
        defineOwn(globalThis, 'Worker', function BlockedWorker() {
            throw new TypeError('blocked by CSP');
        });
        await expect(parallelism()).resolves.toEqual({ state: 'unavailable', reason: 'blocked' });
    });

    it('buckets at the documented boundaries', () => {
        expect([1, 2.5, 2.51, 4.68, 5, 5.01, 9.5, 9.51].map(parallelismBucket)).toEqual(['1-2', '1-2', '3-4', '3-4', '3-4', '5-8', '5-8', '9+']);
    });

    it('keeps the stable tier-2 claims identical across collections (timings and capacity stripped by name)', async () => {
        installSpinWorkers(4);
        const challenge = { token: 't', purpose: 'signin' as const, expiresAt: 0 };
        const strip = (claims: unknown): string =>
            JSON.stringify(claims, (key, value) => (key === 'timing' || key === 'elapsedMs' ? undefined : value));

        const first = await collectTier2(challenge, 'signin');
        const second = await collectTier2(challenge, 'signin');

        expect((first.claims.tier2 as Record<string, unknown>).parallelism).toEqual({ bucket: '3-4', elapsedMs: expect.any(Object) });
        expect(strip(first.claims)).toBe(strip(second.claims));
        expect(first.digest).toBe(second.digest);
    });
});

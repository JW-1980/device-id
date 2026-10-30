/**
 * The specified-value read-back invariants and the presence check:
 *
 * - `canvasFill` and `webdriverPresence` (integrity), and their findings
 *   `canvas_readback_perturbed` and `webdriver_missing`;
 * - `audioReadback` (tier 2);
 * - `permissions.notificationPermission`.
 *
 * jsdom has no 2D context, no `OfflineAudioContext`, no `Notification` and no
 * `navigator.webdriver`, so each test installs a small fake that really computes: the
 * canvas fake stores and returns pixels, the audio fake renders a buffer. The findings are
 * shown to FIRE on the tampering they target and to stay silent on a conformant fake. That
 * a stock engine produces none of them is asserted against three real engines in
 * tests/Browser/transport-checks.mjs (check a).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { canvasDual, canvasFill, collectIntegrity, INTEGRITY_CODES, webdriverPresence } from '@device-id/collector/integrity';
import { AUDIO_READBACK_TIMEOUT_MS, audioReadback, permissions, probesOf, TIER } from '@device-id/collector/value-probes';

const undos: Array<() => void> = [];
afterEach(() => {
    vi.useRealTimers();
    while (undos.length) undos.pop()?.();
});

function defineOwn(target: object, name: string, descriptor: PropertyDescriptor): void {
    const original = Object.getOwnPropertyDescriptor(target, name);
    const isAccessor = 'get' in descriptor || 'set' in descriptor;
    Object.defineProperty(target, name, isAccessor ? { configurable: true, ...descriptor } : { configurable: true, writable: true, ...descriptor });
    undos.push(() => {
        if (original) Object.defineProperty(target, name, original);
        else delete (target as Record<string, unknown>)[name];
    });
}

const codesOf = (): string[] => collectIntegrity().findings.map((finding) => finding.code);

// ---------------------------------------------------------------------------
// canvas
// ---------------------------------------------------------------------------

type ReadBack = (data: Uint8ClampedArray, readIndex: number) => Uint8ClampedArray;

function parseColour(colour: string): [number, number, number] {
    const rgb = /^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/.exec(colour);
    if (rgb) return [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])];
    const hex = colour.replace('#', '');
    return [parseInt(hex.slice(0, 2), 16), parseInt(hex.slice(2, 4), 16), parseInt(hex.slice(4, 6), 16)];
}

/** A 2D context that really stores pixels. `readBack` can perturb what `getImageData` returns. */
function installPixelCanvas(readBack: ReadBack = (data) => data, options: { throwOnRead?: boolean; shortRead?: boolean } = {}): void {
    const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
    const original = proto.getContext;
    let reads = 0;
    proto.getContext = function fakeGetContext(this: HTMLCanvasElement, kind: string): unknown {
        if (kind !== '2d') return null;
        const width = this.width;
        const pixels = new Uint8ClampedArray(width * this.height * 4);
        return {
            fillStyle: '#000000',
            fillRect(x: number, y: number, w: number, h: number) {
                const [r, g, b] = parseColour(String(this.fillStyle));
                for (let row = y; row < y + h; row++) {
                    for (let col = x; col < x + w; col++) pixels.set([r, g, b, 0xff], (row * width + col) * 4);
                }
            },
            createImageData(w: number, h: number) {
                return { data: new Uint8ClampedArray(w * h * 4), width: w, height: h };
            },
            putImageData(image: { data: Uint8ClampedArray }) {
                pixels.set(image.data);
            },
            getImageData(x: number, y: number, w: number, h: number) {
                if (options.throwOnRead) throw new TypeError('read-back refused');
                const out = new Uint8ClampedArray(w * h * 4);
                for (let row = 0; row < h; row++) {
                    const from = ((y + row) * width + x) * 4;
                    out.set(pixels.subarray(from, from + w * 4), row * w * 4);
                }
                const data = readBack(out, reads++);
                return { data: options.shortRead ? data.subarray(0, data.length - 8) : data, width: w, height: h };
            },
            fill() {},
        };
    };
    undos.push(() => {
        proto.getContext = original;
    });
}

/** Brave-farbling-like: the same small change for the same content, every read. */
const perSessionNoise: ReadBack = (data) => {
    const copy = new Uint8ClampedArray(data);
    for (let i = 0; i < copy.length; i += 4 * 97) copy[i] = (copy[i] as number) ^ 0x01;
    return copy;
};

/** RFP-like: a different byte flipped on every read. */
const perReadNoise: ReadBack = (data, readIndex) => {
    const copy = new Uint8ClampedArray(data);
    const at = (readIndex * 4 * 37) % copy.length;
    copy[at] = (copy[at] as number) ^ 0x01;
    return copy;
};

describe('canvasFill (integrity)', () => {
    it('reads every pixel of a solid rgb(10,20,30) fill back exactly on an honest canvas, and raises nothing', () => {
        installPixelCanvas();

        expect(canvasFill()).toEqual({ state: 'ok', value: { exact: true, deviations: 0 } });
        const report = collectIntegrity();
        expect(report.findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.CANVAS_READBACK_PERTURBED);
        expect(report.data.canvasFill).toEqual({ state: 'ok', value: { exact: true, deviations: 0 } });
    });

    it('FIRES on deterministic per-session noise — which canvasDual, by design, does not see', () => {
        installPixelCanvas(perSessionNoise);

        // The gap this probe closes: two identical draws read back identically, so the
        // repeat-render check and the dual check both pass...
        const dual = canvasDual();
        expect(dual.state === 'ok' && dual.value.agree).toBe(true);

        // ...but the read-back is not what was drawn.
        const fill = canvasFill();
        expect(fill.state).toBe('ok');
        if (fill.state !== 'ok') return;
        expect(fill.value.exact).toBe(false);
        // 62*62 = 3844 pixels read; noise every 97th pixel of the read region.
        expect(fill.value.deviations).toBe(Math.ceil(3844 / 97));

        const findings = collectIntegrity().findings;
        const perturbed = findings.filter((f) => f.code === INTEGRITY_CODES.CANVAS_READBACK_PERTURBED);
        // The bare code; the deviation count travels in `data.canvasFill`, not in prose.
        expect(perturbed).toEqual([{ code: INTEGRITY_CODES.CANVAS_READBACK_PERTURBED }]);
        expect(findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.CANVAS_DUAL_DIVERGED);
    });

    it('FIRES on per-read randomisation too', () => {
        installPixelCanvas(perReadNoise);

        const fill = canvasFill();
        expect(fill.state === 'ok' && fill.value).toEqual({ exact: false, deviations: 1 });
        expect(codesOf()).toContain(INTEGRITY_CODES.CANVAS_READBACK_PERTURBED);
    });

    it('checks all four channels: a change to green, blue or alpha alone is a deviation', () => {
        for (const channel of [1, 2, 3]) {
            installPixelCanvas((data) => {
                const copy = new Uint8ClampedArray(data);
                copy[4 * 5 + channel] = (copy[4 * 5 + channel] as number) ^ 0x01;
                return copy;
            });

            expect(canvasFill(), `channel ${channel}`).toEqual({ state: 'ok', value: { exact: false, deviations: 1 } });
            undos.pop()?.();
        }
    });

    it('counts a short read as deviations instead of passing it', () => {
        installPixelCanvas(undefined, { shortRead: true });

        expect(canvasFill()).toEqual({ state: 'ok', value: { exact: false, deviations: 2 } });
    });

    it('is unavailable without a 2D context, and raises nothing', () => {
        // jsdom's own behaviour: getContext() returns null.
        expect(canvasFill()).toEqual({ state: 'unavailable', reason: 'no-2d-context' });
        expect(codesOf()).not.toContain(INTEGRITY_CODES.CANVAS_READBACK_PERTURBED);
    });

    it('is an error, not a finding, when the read-back throws', () => {
        installPixelCanvas(undefined, { throwOnRead: true });

        expect(canvasFill()).toEqual({ state: 'error', name: 'TypeError' });
        expect(codesOf()).not.toContain(INTEGRITY_CODES.CANVAS_READBACK_PERTURBED);
    });
});

// ---------------------------------------------------------------------------
// webdriver
// ---------------------------------------------------------------------------

/** A conformant attribute: a getter on Navigator.prototype returning false. */
function installWebdriverAttribute(): void {
    defineOwn(Navigator.prototype, 'webdriver', { get: () => false, enumerable: true });
}

describe('webdriverPresence (integrity)', () => {
    it('stays silent when navigator.webdriver exists and reads false', () => {
        installWebdriverAttribute();

        expect(webdriverPresence()).toEqual({ state: 'ok', value: { present: true } });
        const report = collectIntegrity();
        expect(report.findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.WEBDRIVER_MISSING);
        expect(report.data.webdriverPresence).toEqual({ state: 'ok', value: { present: true } });
    });

    it('stays silent when automation is ON (true is a value, not a deletion)', () => {
        defineOwn(Navigator.prototype, 'webdriver', { get: () => true });

        expect(codesOf()).not.toContain(INTEGRITY_CODES.WEBDRIVER_MISSING);
    });

    it('FIRES when the attribute has been deleted, as a stealth plugin does', () => {
        installWebdriverAttribute();
        expect(codesOf()).not.toContain(INTEGRITY_CODES.WEBDRIVER_MISSING);

        delete (Navigator.prototype as unknown as Record<string, unknown>).webdriver;

        expect('webdriver' in navigator).toBe(false);
        expect(webdriverPresence()).toEqual({ state: 'ok', value: { present: false } });
        const missing = collectIntegrity().findings.filter((f) => f.code === INTEGRITY_CODES.WEBDRIVER_MISSING);
        expect(missing).toEqual([{ code: INTEGRITY_CODES.WEBDRIVER_MISSING }]);
    });

    it('FIRES in plain jsdom, which genuinely has no navigator.webdriver', () => {
        expect('webdriver' in navigator).toBe(false);

        expect(codesOf()).toContain(INTEGRITY_CODES.WEBDRIVER_MISSING);
    });

    it('keeps the existing integrity data keys and adds the two new ones', () => {
        // Add, never rename: the keys that existed keep their names and order; probes added
        // later (lieBattery, phantomRealm, resistance) may follow them.
        expect(Object.keys(collectIntegrity().data).slice(0, 7)).toEqual([
            'wrongReceiver', 'descriptorIntegrity', 'mathDual', 'canvasDual', 'domBlockers', 'webdriverPresence', 'canvasFill',
        ]);
        expect(INTEGRITY_CODES.WEBDRIVER_MISSING).toBe('webdriver_missing');
        expect(INTEGRITY_CODES.CANVAS_READBACK_PERTURBED).toBe('canvas_readback_perturbed');
    });
});

// ---------------------------------------------------------------------------
// audio
// ---------------------------------------------------------------------------

interface FakeAudioOptions {
    /** Transform applied to the rendered samples as `getChannelData` returns them. */
    direct?: (samples: Float32Array) => Float32Array;
    /** Transform applied to what `copyFromChannel` writes. */
    copy?: (samples: Float32Array) => Float32Array;
    render?: 'ok' | 'never' | 'reject';
    /** Noise the analyser adds to its (silent) bins, as Brave's strict farbling does. */
    analyserNoise?: boolean;
    /** Install the `AudioBuffer` constructor (the trap check needs it). */
    audioBufferConstructor?: boolean;
    /** Make `createOscillator` throw, to show one sub-check failing alone. */
    oscillatorThrows?: boolean;
}

/** A buffer that really stores samples, and applies the read-path transforms. */
class FakeAudioBuffer {
    readonly samples: Float32Array;
    static direct: (samples: Float32Array) => Float32Array = (s) => s;
    static copy: (samples: Float32Array) => Float32Array = (s) => s;
    constructor(options: { length: number; sampleRate: number }) {
        this.samples = new Float32Array(options.length);
    }
    get length(): number {
        return this.samples.length;
    }
    getChannelData(): Float32Array {
        return FakeAudioBuffer.direct(this.samples);
    }
    copyFromChannel(target: Float32Array): void {
        target.set(FakeAudioBuffer.copy(new Float32Array(this.samples)));
    }
    copyToChannel(source: Float32Array, _channel: number, start = 0): void {
        this.samples.set(source, start);
    }
}

/**
 * An OfflineAudioContext that really renders: a started, connected ConstantSourceNode fills
 * the buffer with its offset; a started, connected sine OscillatorNode writes
 * sin(2π f t), which is exactly 0 for f = 0.
 */
function installFakeOfflineAudio({
    direct = (s) => s,
    copy = (s) => s,
    render = 'ok',
    analyserNoise = false,
    audioBufferConstructor = true,
    oscillatorThrows = false,
}: FakeAudioOptions = {}): { contexts: number[][] } {
    const contexts: number[][] = [];
    FakeAudioBuffer.direct = direct;
    FakeAudioBuffer.copy = copy;

    class FakeNode {
        started = false;
        connected = false;
        connect(): void {
            this.connected = true;
        }
        start(): void {
            this.started = true;
        }
    }
    class FakeConstantSourceNode extends FakeNode {
        offset = { value: 1 };
    }
    class FakeOscillatorNode extends FakeNode {
        frequency = { value: 440 };
    }

    class FakeOfflineAudioContext {
        readonly destination = {};
        readonly nodes: FakeNode[] = [];
        constructor(readonly channels: number, readonly length: number, readonly sampleRate: number) {
            contexts.push([channels, length, sampleRate]);
        }
        createConstantSource(): FakeConstantSourceNode {
            const node = new FakeConstantSourceNode();
            this.nodes.push(node);
            return node;
        }
        createOscillator(): FakeOscillatorNode {
            if (oscillatorThrows) throw new TypeError('no oscillators here');
            const node = new FakeOscillatorNode();
            this.nodes.push(node);
            return node;
        }
        createAnalyser(): { frequencyBinCount: number; getFloatFrequencyData(bins: Float32Array): void } {
            return {
                frequencyBinCount: 1024,
                getFloatFrequencyData(bins: Float32Array) {
                    bins.fill(-Infinity);
                    if (analyserNoise) bins[17] = -143.25;
                },
            };
        }
        startRendering(): Promise<unknown> {
            if (render === 'never') return new Promise(() => undefined);
            if (render === 'reject') return Promise.reject(new RangeError('render failed'));
            const buffer = new FakeAudioBuffer({ length: this.length, sampleRate: this.sampleRate });
            for (const node of this.nodes) {
                if (!node.started || !node.connected) continue;
                if (node instanceof FakeConstantSourceNode) buffer.samples.fill(node.offset.value);
                if (node instanceof FakeOscillatorNode) {
                    for (let i = 0; i < this.length; i++) {
                        buffer.samples[i] = Math.sin((2 * Math.PI * node.frequency.value * i) / this.sampleRate);
                    }
                }
            }
            return Promise.resolve(buffer);
        }
    }

    defineOwn(window, 'OfflineAudioContext', { value: FakeOfflineAudioContext });
    defineOwn(globalThis, 'ConstantSourceNode', { value: FakeConstantSourceNode });
    if (audioBufferConstructor) defineOwn(globalThis, 'AudioBuffer', { value: FakeAudioBuffer });

    return { contexts };
}

const ALL_EXACT = { constantExact: true, methodsAgree: true, distinct: 1, silenceExact: true, analyserSilent: true, trapSurvives: true };

describe('audioReadback (tier 2)', () => {
    it('is registered in tier 2 directly after timezoneLmt; audioOffline is scheduled late (decision D5)', () => {
        const names = probesOf(TIER.TWO).map((entry) => entry.name);
        expect(names.indexOf('audioReadback')).toBe(names.indexOf('timezoneLmt') + 1);
        expect(probesOf(TIER.TWO).find((entry) => entry.name === 'audioOffline')?.late).toBe(true);
    });

    it('is unavailable (no-offline-audio) under jsdom', async () => {
        expect(typeof (window as { OfflineAudioContext?: unknown }).OfflineAudioContext).toBe('undefined');

        await expect(audioReadback()).resolves.toEqual({ state: 'unavailable', reason: 'no-offline-audio' });
    });

    it('is unavailable (no-offline-audio) with an OfflineAudioContext but no ConstantSourceNode', async () => {
        installFakeOfflineAudio();
        delete (globalThis as Record<string, unknown>).ConstantSourceNode;

        await expect(audioReadback()).resolves.toEqual({ state: 'unavailable', reason: 'no-offline-audio' });
    });

    it('reports every check exact on a conformant engine, with the specified context sizes', async () => {
        const fake = installFakeOfflineAudio();

        await expect(audioReadback()).resolves.toEqual({ state: 'ok', value: ALL_EXACT });
        // The constant render (256), the 0 Hz silence render (128) and the analyser context (1).
        expect(fake.contexts).toEqual(expect.arrayContaining([[1, 256, 44100], [1, 128, 44100], [1, 1, 44100]]));
        expect(fake.contexts).toHaveLength(3);
    });

    it('detects multiplicative noise on getChannelData (Brave-style farbling) in the constant, the silence and the trap', async () => {
        installFakeOfflineAudio({ direct: (s) => s.map((v, i) => (v === 0 ? 1e-7 * (i % 3) : v * (1 + (i % 3) * 1e-7))) });

        const result = await audioReadback();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.constantExact).toBe(false);
        expect(result.value.distinct).toBeGreaterThan(1);
        // Only one path was wrapped, so the two read methods also disagree.
        expect(result.value.methodsAgree).toBe(false);
        expect(result.value.silenceExact).toBe(false);
        expect(result.value.trapSurvives).toBe(false);
        expect(result.value.analyserSilent).toBe(true);
    });

    it('detects a wrapper on copyFromChannel alone, through methodsAgree and the trap', async () => {
        installFakeOfflineAudio({ copy: (s) => s.map((v, i) => (i === 7 ? v + 1e-6 : v)) });

        await expect(audioReadback()).resolves.toEqual({
            state: 'ok',
            value: { ...ALL_EXACT, methodsAgree: false, trapSurvives: false },
        });
    });

    it('detects noise applied identically to both read paths through exactness', async () => {
        const noisy = (s: Float32Array): Float32Array => s.map((v, i) => (i % 2 ? v + 1e-6 : v));
        installFakeOfflineAudio({ direct: noisy, copy: noisy });

        await expect(audioReadback()).resolves.toEqual({
            state: 'ok',
            value: { ...ALL_EXACT, constantExact: false, distinct: 2, silenceExact: false, trapSurvives: false },
        });
    });

    it('detects a farbled analyser (Brave strict) while the sample paths stay exact', async () => {
        installFakeOfflineAudio({ analyserNoise: true });

        await expect(audioReadback()).resolves.toEqual({ state: 'ok', value: { ...ALL_EXACT, analyserSilent: false } });
    });

    it('detects a trap value that moved or changed on both read paths', async () => {
        // Noise that only touches non-zero samples: the constant and the trap change, the
        // silent render and the zeros of the trap buffer do not.
        installFakeOfflineAudio({ direct: (s) => s.map((v) => (v === 0 ? 0 : v * 1.0000001)), copy: (s) => s.map((v) => (v === 0 ? 0 : v * 1.0000001)) });

        const result = await audioReadback();
        expect(result.state === 'ok' && result.value).toEqual({ ...ALL_EXACT, constantExact: false, trapSurvives: false });
    });

    it('reports null for a check that cannot run, without taking the others down', async () => {
        installFakeOfflineAudio({ audioBufferConstructor: false, oscillatorThrows: true });

        await expect(audioReadback()).resolves.toEqual({
            state: 'ok',
            value: { ...ALL_EXACT, silenceExact: null, trapSurvives: null },
        });
    });

    it('is an error, not a throw, when rendering rejects', async () => {
        installFakeOfflineAudio({ render: 'reject' });

        await expect(audioReadback()).resolves.toEqual({ state: 'error', name: 'RangeError' });
    });

    it('settles as unavailable (timeout) when rendering never completes', async () => {
        vi.useFakeTimers();
        installFakeOfflineAudio({ render: 'never' });

        const pending = audioReadback();
        await vi.advanceTimersByTimeAsync(AUDIO_READBACK_TIMEOUT_MS);

        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'timeout' });
    });
});

// ---------------------------------------------------------------------------
// permissions.notificationPermission
// ---------------------------------------------------------------------------

describe('permissions.notificationPermission', () => {
    const queryAll = (state: string) => ({ query: async () => ({ state }) });

    it('is null when Notification is undefined (jsdom, Android WebView)', async () => {
        expect(typeof (globalThis as { Notification?: unknown }).Notification).toBe('undefined');
        defineOwn(navigator, 'permissions', { value: queryAll('prompt') });

        const result = await permissions();
        expect(result.state === 'ok' && result.value.notificationPermission).toBeNull();
    });

    it('reports Notification.permission next to the query vector — the headless denied/prompt pair', async () => {
        defineOwn(globalThis, 'Notification', { value: { permission: 'denied' } });
        defineOwn(navigator, 'permissions', { value: queryAll('prompt') });

        const result = await permissions();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.notificationPermission).toBe('denied');
        expect(String(result.value.states)).toContain('notifications=prompt');
    });

    it('reports each specified value, and null for anything else', async () => {
        defineOwn(navigator, 'permissions', { value: queryAll('prompt') });
        for (const [permission, expected] of [['default', 'default'], ['granted', 'granted'], ['denied', 'denied'], ['allowed', null], [1, null]] as const) {
            defineOwn(globalThis, 'Notification', { value: { permission } });
            const result = await permissions();
            expect(result.state === 'ok' && result.value.notificationPermission).toBe(expected);
        }
    });

    it('is null, and does not fail the probe, when the getter throws', async () => {
        defineOwn(globalThis, 'Notification', { value: Object.defineProperty({}, 'permission', { get: () => { throw new Error('hostile'); } }) });
        defineOwn(navigator, 'permissions', { value: queryAll('granted') });

        const result = await permissions();
        expect(result.state).toBe('ok');
        expect(result.state === 'ok' && result.value.notificationPermission).toBeNull();
    });

    it('is reported even where the Permissions API is absent', async () => {
        defineOwn(globalThis, 'Notification', { value: { permission: 'default' } });
        defineOwn(navigator, 'permissions', { value: undefined });

        await expect(permissions()).resolves.toEqual({ state: 'ok', value: { supported: false, notificationPermission: 'default' } });
    });
});

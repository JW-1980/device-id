/**
 * notes/22 M1 `gpuMath` and M2 `canvasRealm`, and the WebGL 2 lie targets.
 *
 * jsdom has no canvas and no WebGL, so each test installs a fake that really computes: a 2D
 * context that stores pixels (`fillRect` writes them, `getImageData` reads them back through
 * an optional noise hook) and a WebGL context that records the calls made on it and returns
 * scripted pixels from `readPixels`. That a real engine rasterises identically in both realms
 * and that `gpuMath` is stable across loads is asserted in tests/Browser/transport-checks.mjs.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { fnv1a32 } from '@device-id/collector/canonical';
import { INTEGRITY_CODES, collectIntegrity } from '@device-id/collector/integrity';
import { LIE_TARGETS } from '@device-id/collector/phantom';
import {
    CANVAS_REALM_HEIGHT,
    CANVAS_REALM_WIDTH,
    SCOPE_REPLY_KIND,
    canvasRealmHash,
    fnv1a32Bytes,
    sanitiseReply,
    scopeSnapshot,
    type RealmContext2D,
} from '@device-id/collector/realm';
import { releaseShared } from '@device-id/collector/shared';
import { gpuMath, isSoftwareRenderer, probesOf, TIER, workerScope } from '@device-id/collector/value-probes';

const undos: Array<() => void> = [];
afterEach(() => {
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

// ---------------------------------------------------------------------------
// A 2D context that stores pixels
// ---------------------------------------------------------------------------

type ReadBack = (data: Uint8ClampedArray, readIndex: number) => Uint8ClampedArray;

function parseColour(colour: string): [number, number, number, number] {
    const match = /^rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)$/.exec(colour);
    if (!match) return [0, 0, 0, 255];
    return [Number(match[1]), Number(match[2]), Number(match[3]), Math.round(Number(match[4] ?? 1) * 255)];
}

/** A pixel-storing context: `fillRect` blends source-over or multiply; paths are recorded, not rasterised. */
function pixelContext(width: number, height: number, readBack: ReadBack = (data) => data): RealmContext2D & { calls: string[] } {
    const pixels = new Uint8ClampedArray(width * height * 4);
    const calls: string[] = [];
    let reads = 0;
    return {
        calls,
        fillStyle: '#000000',
        strokeStyle: '#000000',
        lineWidth: 1,
        globalCompositeOperation: 'source-over',
        fillRect(x: number, y: number, w: number, h: number) {
            calls.push(`fillRect ${String(this.fillStyle)} ${this.globalCompositeOperation}`);
            const [r, g, b, a] = parseColour(String(this.fillStyle));
            for (let row = Math.max(0, Math.floor(y)); row < Math.min(height, Math.ceil(y + h)); row++) {
                for (let col = Math.max(0, Math.floor(x)); col < Math.min(width, Math.ceil(x + w)); col++) {
                    const o = (row * width + col) * 4;
                    const mix = (dst: number, src: number): number =>
                        this.globalCompositeOperation === 'multiply'
                            ? Math.round(dst * (1 - a / 255) + ((dst * src) / 255) * (a / 255))
                            : Math.round(dst * (1 - a / 255) + src * (a / 255));
                    pixels[o] = mix(pixels[o] as number, r);
                    pixels[o + 1] = mix(pixels[o + 1] as number, g);
                    pixels[o + 2] = mix(pixels[o + 2] as number, b);
                    pixels[o + 3] = 255;
                }
            }
        },
        beginPath: () => calls.push('beginPath'),
        arc: () => calls.push('arc'),
        closePath: () => calls.push('closePath'),
        fill: () => calls.push('fill'),
        moveTo: () => calls.push('moveTo'),
        bezierCurveTo: () => calls.push('bezierCurveTo'),
        stroke: () => calls.push('stroke'),
        getImageData(x: number, y: number, w: number, h: number) {
            calls.push('getImageData');
            const out = new Uint8ClampedArray(w * h * 4);
            for (let row = 0; row < h; row++) out.set(pixels.subarray(((y + row) * width + x) * 4, ((y + row) * width + x + w) * 4), row * w * 4);
            return { data: readBack(out, reads++), width: w, height: h, colorSpace: 'srgb' } as ImageData;
        },
    } as unknown as RealmContext2D & { calls: string[] };
}

/** A deterministic page-only noiser: flips one bit in every 97th pixel, every read alike. */
const deterministicNoise: ReadBack = (data) => {
    const copy = new Uint8ClampedArray(data);
    for (let i = 0; i < copy.length; i += 4 * 97) copy[i] = (copy[i] as number) ^ 0x01;
    return copy;
};

/** Per-read noise (RFP-like): a different byte on every read. */
const perReadNoise: ReadBack = (data, readIndex) => {
    const copy = new Uint8ClampedArray(data);
    copy[(readIndex * 4 * 37) % copy.length] ^= 0x01;
    return copy;
};

/** Install the pixel context behind `HTMLCanvasElement.getContext('2d')`, recording the options. */
function installPageCanvas(readBack?: ReadBack): { options: unknown[]; sizes: string[]; attached: boolean[] } {
    const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
    const original = proto.getContext;
    const record = { options: [] as unknown[], sizes: [] as string[], attached: [] as boolean[] };
    proto.getContext = function (this: HTMLCanvasElement, kind: string, options?: unknown): unknown {
        if (kind !== '2d') return null;
        record.options.push(options);
        record.sizes.push(`${this.width}x${this.height}`);
        record.attached.push(this.isConnected);
        return pixelContext(this.width, this.height, readBack);
    };
    undos.push(() => {
        proto.getContext = original;
    });
    return record;
}

// ---------------------------------------------------------------------------
// M2 canvasRealm
// ---------------------------------------------------------------------------

describe('canvasRealmHash (M2)', () => {
    it('hashes the scene as 8 hex digits, deterministically, with no text drawn', () => {
        const a = pixelContext(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT);
        const hash = canvasRealmHash(a);
        expect(hash).toMatch(/^[0-9a-f]{8}$/);
        expect(canvasRealmHash(pixelContext(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT))).toBe(hash);
        expect(a.calls.some((call) => /text/i.test(call))).toBe(false);
        expect(a.calls.filter((call) => call === 'getImageData')).toHaveLength(2);
    });

    it('is null without a context, when the two reads disagree, when a read throws, or on a short read', () => {
        expect(canvasRealmHash(null)).toBeNull();
        expect(canvasRealmHash(pixelContext(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT, perReadNoise))).toBeNull();
        const throwing = pixelContext(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT);
        throwing.getImageData = () => {
            throw new TypeError('blocked');
        };
        expect(canvasRealmHash(throwing)).toBeNull();
        expect(canvasRealmHash(pixelContext(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT, (data) => data.subarray(4)))).toBeNull();
    });

    it('changes under deterministic noise (which the two-read check cannot see)', () => {
        const clean = canvasRealmHash(pixelContext(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT));
        const noisy = canvasRealmHash(pixelContext(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT, deterministicNoise));
        expect(noisy).toMatch(/^[0-9a-f]{8}$/);
        expect(noisy).not.toBe(clean);
    });

    it('fnv1a32Bytes is canonical fnv1a32 over the same byte values', () => {
        const bytes = [0, 1, 127, 128, 200, 255, 42];
        expect(fnv1a32Bytes(bytes)).toBe(fnv1a32(String.fromCharCode(...bytes)));
        expect(fnv1a32Bytes(new Uint8ClampedArray(0))).toBe(fnv1a32(''));
    });

    it('sanitiseReply keeps only an 8-hex canvasHash', () => {
        const snapshot = scopeSnapshot({ vendor: null, renderer: null }, 'deadbeef');
        expect(sanitiseReply({ kind: SCOPE_REPLY_KIND, snapshot })?.canvasHash).toBe('deadbeef');
        for (const bad of ['DEADBEEF', 'deadbee', 'deadbeef0', 7, { toString: () => 'deadbeef' }]) {
            expect(sanitiseReply({ kind: SCOPE_REPLY_KIND, snapshot: { ...snapshot, canvasHash: bad } })?.canvasHash).toBeNull();
        }
    });
});

describe('workerScope carries canvasRealm (M2)', () => {
    /** The worker realm, simulated: its own clean pixel context, as OffscreenCanvas would give. */
    const workerReply = () => ({
        kind: SCOPE_REPLY_KIND,
        snapshot: scopeSnapshot({ vendor: null, renderer: null }, canvasRealmHash(pixelContext(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT))),
    });

    function installReplyingWorker(): void {
        class ReplyingWorker extends EventTarget {
            postMessage(): void {
                queueMicrotask(() => this.dispatchEvent(new MessageEvent('message', { data: workerReply() })));
            }
            terminate(): void {}
        }
        defineOwn(globalThis, 'Worker', ReplyingWorker);
    }

    it('reports EQUAL hashes for an untouched page canvas, from a detached 160x64 willReadFrequently canvas', async () => {
        installReplyingWorker();
        const page = installPageCanvas();

        const result = await workerScope();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.window.canvasHash).toMatch(/^[0-9a-f]{8}$/);
        expect(result.value.window.canvasHash).toBe(result.value.worker.canvasHash);
        expect(page.options).toEqual([{ willReadFrequently: true }]);
        expect(page.sizes).toEqual([`${CANVAS_REALM_WIDTH}x${CANVAS_REALM_HEIGHT}`]);
        expect(page.attached).toEqual([false]);
    });

    it('reports DIFFERENT hashes when a page-only getImageData noiser is installed — and raises no client finding', async () => {
        installReplyingWorker();
        installPageCanvas(deterministicNoise);

        const result = await workerScope();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.window.canvasHash).toMatch(/^[0-9a-f]{8}$/);
        expect(result.value.worker.canvasHash).toMatch(/^[0-9a-f]{8}$/);
        expect(result.value.window.canvasHash).not.toBe(result.value.worker.canvasHash);

        // The comparison is the server's (canvas_realm_mismatch); the client has no such code.
        expect(Object.values(INTEGRITY_CODES)).not.toContain('canvas_realm_mismatch');
        expect(collectIntegrity().findings.map((f) => f.code)).not.toContain('canvas_realm_mismatch');
    });

    it('reports a null window hash under per-read randomisation, not a mismatch', async () => {
        installReplyingWorker();
        installPageCanvas(perReadNoise);

        const result = await workerScope();
        expect(result.state === 'ok' && result.value.window.canvasHash).toBeNull();
    });
});

// ---------------------------------------------------------------------------
// M1 gpuMath
// ---------------------------------------------------------------------------

const GL = {
    VENDOR: 0x1f00, RENDERER: 0x1f01, FRAGMENT_SHADER: 0x8b30, VERTEX_SHADER: 0x8b31, HIGH_FLOAT: 0x8df2, MEDIUM_FLOAT: 0x8df1,
    COMPILE_STATUS: 0x8b81, LINK_STATUS: 0x8b82, TEXTURE_2D: 0x0de1, RGBA: 0x1908, UNSIGNED_BYTE: 0x1401, NEAREST: 0x2600,
    TEXTURE_MIN_FILTER: 0x2801, TEXTURE_MAG_FILTER: 0x2800, FRAMEBUFFER: 0x8d40, COLOR_ATTACHMENT0: 0x8ce0,
    FRAMEBUFFER_COMPLETE: 0x8cd5, DITHER: 0x0bd0, ARRAY_BUFFER: 0x8892, STATIC_DRAW: 0x88e4, FLOAT: 0x1406, TRIANGLES: 0x0004,
    FRAMEBUFFER_BINDING: 0x8ca6, CURRENT_PROGRAM: 0x8b8d, ARRAY_BUFFER_BINDING: 0x8894, TEXTURE_BINDING_2D: 0x8069, VIEWPORT: 0x0ba2,
};
const DEBUG = { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 };
const PIXELS = Uint8Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 0xff);

interface FakeGlOptions {
    renderer?: string;
    highp?: number;
    compileOk?: boolean;
    linkOk?: boolean;
    complete?: boolean;
    readNoise?: boolean;
    drawThrows?: boolean;
}

function installGpuMathGl(options: FakeGlOptions = {}): { log: string[]; state: Record<string, unknown>; sources: string[] } {
    const { renderer = 'NVIDIA GeForce RTX 4090', highp = 23, compileOk = true, linkOk = true, complete = true, readNoise = false, drawThrows = false } = options;
    const log: string[] = [];
    const sources: string[] = [];
    const state: Record<string, unknown> = { dither: true, framebuffer: 'previous-fb', program: 'previous-program', buffer: 'previous-buffer', texture: 'previous-texture', viewport: [0, 0, 300, 150] };
    let reads = 0;
    const gl = {
        ...GL,
        getShaderPrecisionFormat: (_shader: number, kind: number) => ({ rangeMin: 127, rangeMax: 127, precision: kind === GL.HIGH_FLOAT ? highp : 10 }),
        getExtension: (name: string) => (name === 'WEBGL_debug_renderer_info' ? DEBUG : null),
        getParameter: (pname: number) =>
            ({
                [DEBUG.UNMASKED_RENDERER_WEBGL]: renderer, [DEBUG.UNMASKED_VENDOR_WEBGL]: 'Vendor', [GL.RENDERER]: 'WebKit WebGL',
                [GL.FRAMEBUFFER_BINDING]: state.framebuffer, [GL.CURRENT_PROGRAM]: state.program, [GL.ARRAY_BUFFER_BINDING]: state.buffer,
                [GL.TEXTURE_BINDING_2D]: state.texture, [GL.VIEWPORT]: Int32Array.from(state.viewport as number[]),
            })[pname],
        isEnabled: (cap: number) => (cap === GL.DITHER ? state.dither : false),
        enable: (cap: number) => { if (cap === GL.DITHER) state.dither = true; log.push('enable'); },
        disable: (cap: number) => { if (cap === GL.DITHER) state.dither = false; log.push('disable'); },
        createShader: () => ({ kind: 'shader' }),
        shaderSource: (_s: unknown, source: string) => sources.push(source),
        compileShader: () => undefined,
        getShaderParameter: () => compileOk,
        createProgram: () => 'new-program',
        attachShader: () => undefined,
        linkProgram: () => undefined,
        getProgramParameter: () => linkOk,
        createTexture: () => 'new-texture',
        createFramebuffer: () => 'new-fb',
        createBuffer: () => 'new-buffer',
        bindTexture: (_t: number, texture: unknown) => { state.texture = texture; },
        texImage2D: () => undefined,
        texParameteri: () => undefined,
        bindFramebuffer: (_t: number, fb: unknown) => { state.framebuffer = fb; },
        framebufferTexture2D: () => undefined,
        checkFramebufferStatus: () => (complete ? GL.FRAMEBUFFER_COMPLETE : 0),
        viewport: (...args: number[]) => { state.viewport = args; log.push(`viewport ${args.join(',')}`); },
        useProgram: (program: unknown) => { state.program = program; },
        bindBuffer: (_t: number, buffer: unknown) => { state.buffer = buffer; },
        bufferData: () => undefined,
        getAttribLocation: () => 0,
        enableVertexAttribArray: () => log.push('enableAttrib'),
        disableVertexAttribArray: () => log.push('disableAttrib'),
        vertexAttribPointer: () => undefined,
        drawArrays: () => {
            if (drawThrows) throw new TypeError('context lost');
            log.push(`draw dither=${String(state.dither)} fb=${String(state.framebuffer)}`);
        },
        readPixels: (x: number, y: number, w: number, h: number, format: number, type: number, out: Uint8Array) => {
            log.push(`read ${x},${y},${w},${h},${format === GL.RGBA},${type === GL.UNSIGNED_BYTE} fb=${String(state.framebuffer)}`);
            out.set(PIXELS);
            if (readNoise && reads++ > 0) out[5] = (out[5] as number) ^ 1;
        },
        deleteShader: () => log.push('deleteShader'),
        deleteProgram: () => log.push('deleteProgram'),
        deleteTexture: () => log.push('deleteTexture'),
        deleteFramebuffer: () => log.push('deleteFramebuffer'),
        deleteBuffer: () => log.push('deleteBuffer'),
        getSupportedExtensions: () => [],
    };

    const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
    const original = proto.getContext;
    proto.getContext = (kind: string): unknown => (kind === 'webgl2' || kind === 'webgl' ? gl : null);
    undos.push(() => {
        proto.getContext = original;
    });
    defineOwn(globalThis, 'WebGL2RenderingContext', function WebGL2RenderingContext() {});
    releaseShared();

    return { log, state, sources };
}

describe('gpuMath (M1)', () => {
    it('is registered in the hardware tier directly after gpu', () => {
        const names = probesOf(TIER.HARDWARE).map((p) => p.name);
        expect(names.indexOf('gpuMath')).toBe(names.indexOf('gpu') + 1);
    });

    it('is unavailable (no-webgl) under jsdom', () => {
        expect(gpuMath()).toEqual({ state: 'unavailable', reason: 'no-webgl' });
    });

    it('hashes the 64 read bytes, records the precision class, and is stable across calls', () => {
        installGpuMathGl();

        const result = gpuMath();
        expect(result).toEqual({ state: 'ok', value: { hash: fnv1a32Bytes(PIXELS), precision: 'highp:23', software: false } });
        expect(gpuMath()).toEqual(result);
    });

    it('renders all four channels as amplified functions of BOTH coordinates', () => {
        const fake = installGpuMathGl();
        gpuMath();

        const fragment = fake.sources.find((source) => source.includes('gl_FragColor')) ?? '';
        for (const expression of ['sin(x * 7.0 + y * 3.0) * 43758.5453', 'exp(x * 3.0 + y) * 1013.0', 'pow(x + 0.5, 2.2 + y) * 611.0', 'log(x + y + 1.5) * 997.0']) {
            expect(fragment).toContain(expression);
        }
    });

    it('draws into its own 4x4 framebuffer with dithering off, reads twice, and restores the shared context', () => {
        const fake = installGpuMathGl();
        gpuMath();

        expect(fake.log).toContain('viewport 0,0,4,4');
        expect(fake.log).toContain('draw dither=false fb=new-fb');
        expect(fake.log.filter((line) => line === 'read 0,0,4,4,true,true fb=new-fb')).toHaveLength(2);
        expect(fake.state).toEqual({
            dither: true, framebuffer: 'previous-fb', program: 'previous-program', buffer: 'previous-buffer',
            texture: 'previous-texture', viewport: [0, 0, 300, 150],
        });
        for (const deleted of ['deleteShader', 'deleteProgram', 'deleteTexture', 'deleteFramebuffer', 'deleteBuffer', 'disableAttrib']) {
            expect(fake.log).toContain(deleted);
        }
    });

    it('is unavailable (randomised) when the two reads differ', () => {
        installGpuMathGl({ readNoise: true });
        expect(gpuMath()).toEqual({ state: 'unavailable', reason: 'randomised' });
    });

    it('records mediump when highp is not supported (mobile GPUs)', () => {
        installGpuMathGl({ highp: 0 });
        expect((gpuMath() as { value: { precision: string } }).value.precision).toBe('mediump:10');
    });

    it('is unavailable (compile-failed) when a shader does not compile or the program does not link, and still cleans up', () => {
        const fake = installGpuMathGl({ compileOk: false });
        expect(gpuMath()).toEqual({ state: 'unavailable', reason: 'compile-failed' });
        expect(fake.log).toContain('deleteProgram');
        undos.splice(0).reverse().forEach((undo) => undo());

        installGpuMathGl({ linkOk: false });
        expect(gpuMath()).toEqual({ state: 'unavailable', reason: 'compile-failed' });
    });

    it('is unavailable (incomplete-framebuffer) when the 4x4 target cannot be rendered to', () => {
        installGpuMathGl({ complete: false });
        expect(gpuMath()).toEqual({ state: 'unavailable', reason: 'incomplete-framebuffer' });
    });

    it('is an error, not a throw, when drawing throws, and restores state anyway', () => {
        const fake = installGpuMathGl({ drawThrows: true });
        expect(gpuMath()).toEqual({ state: 'error', name: 'TypeError' });
        expect(fake.state.dither).toBe(true);
        expect(fake.state.framebuffer).toBe('previous-fb');
    });

    it('flags software rasterisers, and only them', () => {
        installGpuMathGl({ renderer: 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)' });
        expect((gpuMath() as { value: { software: boolean } }).value.software).toBe(true);

        for (const renderer of ['llvmpipe (LLVM 15.0.7, 256 bits)', 'Microsoft Basic Render Driver', 'ANGLE (Microsoft, WARP, D3D11)', 'softpipe', 'Mesa OffScreen', 'llvmpipe, or similar']) {
            expect(isSoftwareRenderer(renderer), renderer).toBe(true);
        }
        for (const renderer of ['NVIDIA GeForce RTX 4090', 'ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)', 'Apple GPU', 'Adreno (TM) 740', 'Mali-G78']) {
            expect(isSoftwareRenderer(renderer), renderer).toBe(false);
        }
    });
});

// ---------------------------------------------------------------------------
// Lie targets
// ---------------------------------------------------------------------------

describe('WebGL 2 lie targets', () => {
    it('lists WebGL2RenderingContext readPixels, getParameter and getExtension, resolved only where the interface exists', () => {
        const webgl2 = LIE_TARGETS.filter((t) => t.api.startsWith('WebGL2RenderingContext.'));
        expect(webgl2.map((t) => t.api)).toEqual([
            'WebGL2RenderingContext.getParameter', 'WebGL2RenderingContext.getExtension', 'WebGL2RenderingContext.readPixels',
        ]);
        // jsdom has no WebGL2RenderingContext: the getters resolve to nothing, so nothing is "checked".
        for (const target of webgl2) expect(target.get()).toBeUndefined();

        function readPixels(): void {}
        defineOwn(globalThis, 'WebGL2RenderingContext', Object.assign(function WebGL2RenderingContext() {}, { prototype: { readPixels } }));
        expect(webgl2[2]?.get()).toBe(readPixels);
    });
});

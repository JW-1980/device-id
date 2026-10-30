import { afterEach, describe, expect, it } from 'vitest';
import { canvasDual, collectIntegrity, INTEGRITY_CODES } from '@device-id/collector/integrity';

/**
 * `canvasDual` under a randomised canvas read-back (round-1 BR-5).
 *
 * jsdom has no canvas, so each test installs a small in-memory 2D context that really
 * stores pixels: `fillRect` and `putImageData` write them, `getImageData` reads them back,
 * through a `readBack` hook that can add noise. The four cases are the four browsers that
 * matter: an honest one, one that randomises every read (Firefox RFP, Tor Browser,
 * CanvasBlocker), one with deterministic per-session noise (Brave farbling, Firefox FPP),
 * and a stub canvas whose `putImageData` does nothing — the thing the dual check exists
 * to catch, which the randomisation check must not hide.
 */

type ReadBack = (data: Uint8ClampedArray, readIndex: number) => Uint8ClampedArray;

interface FakeOptions {
    readBack?: ReadBack;
    putImageDataWorks?: boolean;
}

let undo: (() => void) | null = null;

afterEach(() => {
    undo?.();
    undo = null;
});

function hexToRgb(colour: string): [number, number, number] {
    const hex = colour.replace('#', '');
    return [parseInt(hex.slice(0, 2), 16), parseInt(hex.slice(2, 4), 16), parseInt(hex.slice(4, 6), 16)];
}

/** Install the fake; returns how many `getImageData` reads happened. */
function installPixelCanvas({ readBack = (data) => data, putImageDataWorks = true }: FakeOptions = {}): { reads: () => number } {
    const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
    const original = proto.getContext;
    let reads = 0;

    proto.getContext = function fakeGetContext(this: HTMLCanvasElement, kind: string): unknown {
        if (kind !== '2d') return null;
        const width = this.width;
        const height = this.height;
        const pixels = new Uint8ClampedArray(width * height * 4);

        return {
            fillStyle: '#000000',
            fillRect(x: number, y: number, w: number, h: number) {
                const [r, g, b] = hexToRgb(String(this.fillStyle));
                for (let row = y; row < y + h; row++) {
                    for (let col = x; col < x + w; col++) {
                        const offset = (row * width + col) * 4;
                        pixels.set([r, g, b, 0xff], offset);
                    }
                }
            },
            createImageData(w: number, h: number) {
                return { data: new Uint8ClampedArray(w * h * 4), width: w, height: h };
            },
            putImageData(image: { data: Uint8ClampedArray }) {
                if (putImageDataWorks) pixels.set(image.data);
            },
            getImageData(x: number, y: number, w: number, h: number) {
                const out = new Uint8ClampedArray(w * h * 4);
                for (let row = 0; row < h; row++) {
                    const from = ((y + row) * width + x) * 4;
                    out.set(pixels.subarray(from, from + w * 4), row * w * 4);
                }
                return { data: readBack(out, reads++), width: w, height: h };
            },
        };
    };

    undo = () => {
        proto.getContext = original;
    };

    return { reads: () => reads };
}

/** Every read differs: a different byte flipped on each call, as RFP's per-read noise does. */
const perReadNoise: ReadBack = (data, readIndex) => {
    const copy = new Uint8ClampedArray(data);
    const at = (readIndex * 4 * 37) % copy.length;
    copy[at] = (copy[at] as number) ^ 0x01;
    return copy;
};

/** The same noise for the same content: a deterministic function of the pixels alone. */
const perSessionNoise: ReadBack = (data) => {
    const copy = new Uint8ClampedArray(data);
    for (let i = 0; i < copy.length; i += 4 * 97) copy[i] = (copy[i] as number) ^ 0x01;
    return copy;
};

describe('canvasDual randomisation check', () => {
    it('reports the duals agreeing on an honest canvas', () => {
        installPixelCanvas();

        const result = canvasDual();

        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.agree).toBe(true);
        expect(result.value.fillHash).toBe(result.value.putHash);
    });

    it('reports `unavailable: randomised` when two identical draws read back differently', () => {
        const fake = installPixelCanvas({ readBack: perReadNoise });

        const result = canvasDual();

        expect(result).toEqual({ state: 'unavailable', reason: 'randomised' });
        // Stopped after the two comparison reads: no further canvases are read (fewer
        // reads is fewer RFP prompts and less work).
        expect(fake.reads()).toBe(2);
    });

    it('emits no canvas finding for a randomised canvas, and keeps the probe state on the wire', () => {
        installPixelCanvas({ readBack: perReadNoise });

        const report = collectIntegrity();
        const codes = report.findings.map((finding) => finding.code);

        expect(codes).not.toContain(INTEGRITY_CODES.CANVAS_DUAL_DIVERGED);
        expect(codes).not.toContain(INTEGRITY_CODES.CANVAS_WINDING_FALSE);
        expect(report.data.canvasDual).toEqual({ state: 'unavailable', reason: 'randomised' });
    });

    it('treats deterministic per-session noise as a readable canvas', () => {
        installPixelCanvas({ readBack: perSessionNoise });

        const result = canvasDual();

        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.agree).toBe(true);
    });

    it('still reports a stub canvas whose putImageData does nothing', () => {
        installPixelCanvas({ putImageDataWorks: false });

        const result = canvasDual();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.agree).toBe(false);

        const codes = collectIntegrity().findings.map((finding) => finding.code);
        expect(codes).toContain(INTEGRITY_CODES.CANVAS_DUAL_DIVERGED);
    });

    it('reports an error, not a finding, when there is no 2D context at all', () => {
        const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
        const original = proto.getContext;
        proto.getContext = () => null;
        undo = () => {
            proto.getContext = original;
        };

        expect(canvasDual()).toEqual({ state: 'error', name: 'Error' });
    });
});

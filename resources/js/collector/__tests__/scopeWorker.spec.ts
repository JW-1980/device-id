/**
 * The worker module itself (`scope.worker.ts`), run in jsdom's global scope.
 *
 * In its own spec file because importing it installs a `message` listener on the global
 * scope for the rest of the file, which must not leak into other suites. jsdom has no
 * `OffscreenCanvas`, so the WebGL fields are null here; the real worker in three engines is
 * covered by tests/Browser/transport-checks.mjs (check h).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { canvasRealmHash, sanitiseReply, SCOPE_REPLY_KIND, SPIN_MAX_MS, SPIN_REPLY_KIND, spinIterations, spinRequestMs, type RealmContext2D } from '@device-id/collector/realm';

afterEach(() => {
    vi.restoreAllMocks();
});

describe('scope.worker', () => {
    it('answers a message with one valid, sanitisable snapshot of its own realm', async () => {
        const posted: unknown[] = [];
        vi.spyOn(window, 'postMessage').mockImplementation(((message: unknown) => {
            posted.push(message);
        }) as typeof window.postMessage);

        await import('@device-id/collector/scope.worker');
        expect(posted).toHaveLength(0); // nothing is sent unasked

        window.dispatchEvent(new MessageEvent('message', { data: 'scope' }));

        expect(posted).toHaveLength(1);
        const reply = posted[0] as { kind: string; snapshot: Record<string, unknown> };
        expect(reply.kind).toBe(SCOPE_REPLY_KIND);
        const snapshot = sanitiseReply(reply);
        expect(snapshot).not.toBeNull();
        // Sanitising changes nothing: every field already had its contract type.
        expect(snapshot).toEqual(reply.snapshot);
        expect(snapshot?.userAgent).toBe(navigator.userAgent);
        expect(snapshot?.engine).toBe('v8');
        expect(snapshot?.webglVendor).toBeNull(); // no OffscreenCanvas in jsdom
    });

    it('does not throw out of the handler when posting the reply fails', async () => {
        vi.spyOn(window, 'postMessage').mockImplementation(() => {
            throw new DOMException('could not be cloned', 'DataCloneError');
        });
        await import('@device-id/collector/scope.worker');

        const errors: unknown[] = [];
        const onError = (event: ErrorEvent): void => {
            errors.push(event.error);
        };
        window.addEventListener('error', onError);
        try {
            window.dispatchEvent(new MessageEvent('message', { data: 'scope' }));
        } finally {
            window.removeEventListener('error', onError);
        }
        expect(errors).toHaveLength(0);
    });

    it('answers { ask: "spin", ms } with a loop count, and a 0 ms ready ping with 0', async () => {
        const posted: unknown[] = [];
        vi.spyOn(window, 'postMessage').mockImplementation(((message: unknown) => {
            posted.push(message);
        }) as typeof window.postMessage);
        await import('@device-id/collector/scope.worker');

        window.dispatchEvent(new MessageEvent('message', { data: { ask: 'spin', ms: 0 } }));
        const started = performance.now();
        window.dispatchEvent(new MessageEvent('message', { data: { ask: 'spin', ms: 15 } }));
        const spent = performance.now() - started;

        expect(posted).toEqual([
            { kind: SPIN_REPLY_KIND, iterations: 0 },
            { kind: SPIN_REPLY_KIND, iterations: expect.any(Number) },
        ]);
        expect(spinIterations(posted[1])).toBeGreaterThan(0);
        expect(spent).toBeGreaterThanOrEqual(14);
    });

    it('clamps a hostile spin duration instead of freezing the worker', async () => {
        const posted: unknown[] = [];
        vi.spyOn(window, 'postMessage').mockImplementation(((message: unknown) => {
            posted.push(message);
        }) as typeof window.postMessage);
        await import('@device-id/collector/scope.worker');

        const started = performance.now();
        window.dispatchEvent(new MessageEvent('message', { data: { ask: 'spin', ms: 60_000 } }));
        const spent = performance.now() - started;

        expect(spinIterations(posted[0])).toBeGreaterThan(0);
        expect(spent).toBeLessThan(SPIN_MAX_MS + 150);
    });
});

describe('scope.worker canvasRealm', () => {
    it('draws the scene on a 160x64 OffscreenCanvas with willReadFrequently and reports its hash', async () => {
        const created: Array<{ size: string; options: unknown }> = [];
        /** A context whose read-back is a fixed function of what was drawn (fill styles only). */
        const fakeContext = (): RealmContext2D => {
            let seed = 0;
            const ctx = {
                fillStyle: '', strokeStyle: '', lineWidth: 1, globalCompositeOperation: 'source-over',
                fillRect() { seed += String(ctx.fillStyle).length; },
                beginPath() {}, arc() {}, closePath() {}, fill() {}, moveTo() {}, bezierCurveTo() {}, stroke() {},
                getImageData: (_x: number, _y: number, w: number, h: number) => ({ data: new Uint8ClampedArray(w * h * 4).fill(seed & 0xff) }),
            };
            return ctx as unknown as RealmContext2D;
        };
        class FakeOffscreenCanvas {
            constructor(readonly width: number, readonly height: number) {}
            getContext(kind: string, options?: unknown): RealmContext2D | null {
                created.push({ size: `${this.width}x${this.height}`, options });
                return kind === '2d' ? fakeContext() : null;
            }
        }
        const original = Object.getOwnPropertyDescriptor(globalThis, 'OffscreenCanvas');
        Object.defineProperty(globalThis, 'OffscreenCanvas', { value: FakeOffscreenCanvas, configurable: true, writable: true });
        const posted: unknown[] = [];
        vi.spyOn(window, 'postMessage').mockImplementation(((message: unknown) => {
            posted.push(message);
        }) as typeof window.postMessage);
        try {
            await import('@device-id/collector/scope.worker');
            window.dispatchEvent(new MessageEvent('message', { data: 'scope' }));
        } finally {
            if (original) Object.defineProperty(globalThis, 'OffscreenCanvas', original);
            else delete (globalThis as Record<string, unknown>).OffscreenCanvas;
        }

        const snapshot = sanitiseReply(posted[0]);
        expect(snapshot?.canvasHash).toBe(canvasRealmHash(fakeContext()));
        expect(created.filter((c) => c.options !== undefined && (c.options as { willReadFrequently?: boolean }).willReadFrequently === true))
            .toContainEqual({ size: '160x64', options: { willReadFrequently: true } });
    });
});

describe('spin protocol helpers', () => {
    it('spinRequestMs recognises only spin requests and clamps ms', () => {
        expect(spinRequestMs('scope')).toBeNull();
        expect(spinRequestMs(null)).toBeNull();
        expect(spinRequestMs({ ask: 'scope', ms: 5 })).toBeNull();
        expect(spinRequestMs({ ask: 'spin', ms: 40 })).toBe(40);
        expect(spinRequestMs({ ask: 'spin', ms: -5 })).toBe(0);
        expect(spinRequestMs({ ask: 'spin', ms: 1e9 })).toBe(SPIN_MAX_MS);
        expect(spinRequestMs({ ask: 'spin', ms: 'forty' })).toBe(0);
        expect(spinRequestMs({ ask: 'spin', ms: Number.NaN })).toBe(0);
    });

    it('spinIterations accepts only { kind: nc-spin, iterations: non-negative integer }', () => {
        expect(spinIterations({ kind: SPIN_REPLY_KIND, iterations: 12 })).toBe(12);
        expect(spinIterations({ kind: SPIN_REPLY_KIND, iterations: 0 })).toBe(0);
        for (const bad of [null, 'x', {}, { kind: SCOPE_REPLY_KIND, iterations: 3 }, { kind: SPIN_REPLY_KIND, iterations: -1 }, { kind: SPIN_REPLY_KIND, iterations: 1.5 }, { kind: SPIN_REPLY_KIND, iterations: '3' }]) {
            expect(spinIterations(bad)).toBeNull();
        }
    });
});

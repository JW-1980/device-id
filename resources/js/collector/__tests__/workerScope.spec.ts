/**
 * `workerScope` (tier 2): the window side of the window-versus-worker comparison.
 *
 * jsdom has no `Worker`, so the first test is the real jsdom behaviour (`no-worker`). The
 * rest install a small fake `Worker` whose reply is scripted per test, which is how every
 * window-side path is exercised: the reply is validated, the window snapshot is read after
 * it, the worker is terminated on every outcome (reply, error, timeout, release), and no
 * path throws. The real worker in three real engines is exercised by
 * tests/Browser/transport-checks.mjs (check h).
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { SCOPE_REPLY_KIND, scopeSnapshot, type ScopeSnapshot } from '@device-id/collector/realm';
import { releaseShared } from '@device-id/collector/shared';
import { probesOf, TIER, WORKER_SCOPE_TIMEOUT_MS, workerScope } from '@device-id/collector/value-probes';
import { collectTier2 } from '@device-id/collector/index';
import type { Challenge } from '@device-id/collector/protocol';

type Behaviour = (worker: FakeWorker, message: unknown) => void;

class FakeWorker extends EventTarget {
    static instances: FakeWorker[] = [];
    static behaviour: Behaviour = () => undefined;
    static throwOnConstruct = false;

    readonly url: string;
    readonly options: unknown;
    terminated = false;
    received: unknown[] = [];

    constructor(url: URL | string, options?: unknown) {
        super();
        if (FakeWorker.throwOnConstruct) throw new DOMException('blocked by CSP', 'SecurityError');
        this.url = String(url);
        this.options = options;
        FakeWorker.instances.push(this);
    }

    postMessage(message: unknown): void {
        this.received.push(message);
        queueMicrotask(() => FakeWorker.behaviour(this, message));
    }

    terminate(): void {
        this.terminated = true;
    }

    /** Deliver a reply, as a real worker would, unless it was terminated first. */
    reply(data: unknown): void {
        if (!this.terminated) this.dispatchEvent(new MessageEvent('message', { data }));
    }
}

const workerSideSnapshot = (): ScopeSnapshot => ({
    ...scopeSnapshot({ vendor: null, renderer: null }, null),
    // Deliberately different from the window, to prove the probe reports what each realm
    // said rather than merging or "correcting" either side.
    userAgent: 'Mozilla/5.0 (worker realm)',
    hardwareConcurrency: 64,
});

let restoreWorker: (() => void) | null = null;

function installFakeWorker(behaviour: Behaviour): void {
    FakeWorker.instances = [];
    FakeWorker.behaviour = behaviour;
    FakeWorker.throwOnConstruct = false;
    const original = Object.getOwnPropertyDescriptor(globalThis, 'Worker');
    Object.defineProperty(globalThis, 'Worker', { value: FakeWorker, configurable: true, writable: true });
    restoreWorker = () => {
        if (original) Object.defineProperty(globalThis, 'Worker', original);
        else delete (globalThis as Record<string, unknown>).Worker;
    };
}

afterEach(() => {
    vi.unstubAllEnvs();
    vi.useRealTimers();
    restoreWorker?.();
    restoreWorker = null;
    releaseShared();
});

describe('workerScope', () => {
    it('is unavailable with reason no-worker under jsdom, which has no Worker', async () => {
        expect(typeof (globalThis as { Worker?: unknown }).Worker).toBe('undefined');

        await expect(workerScope()).resolves.toEqual({ state: 'unavailable', reason: 'no-worker' });
    });

    it('is registered FIRST in tier 2, so its worker starts in the first idle slice', () => {
        expect(probesOf(TIER.TWO)[0]?.name).toBe('workerScope');
    });

    it('creates a same-origin worker for scope.worker.ts (module under the dev server), and reports both snapshots with identical keys', async () => {
        installFakeWorker((worker) => worker.reply({ kind: SCOPE_REPLY_KIND, snapshot: workerSideSnapshot() }));

        const result = await workerScope();

        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        const [worker] = FakeWorker.instances;
        expect(worker?.url).toMatch(/scope\.worker/);
        expect(worker?.url).not.toMatch(/^(blob|data):/);
        expect(worker?.options).toEqual({ type: 'module' });
        expect(worker?.terminated).toBe(true);

        expect(result.value.workerType).toBe('dedicated');
        expect(Object.keys(result.value)).toEqual(['workerType', 'window', 'worker', 'elapsedMs']);
        expect(Object.keys(result.value.window)).toEqual(Object.keys(result.value.worker));
        expect(typeof result.value.elapsedMs).toBe('number');
        // Each realm's own values, unmerged.
        expect(result.value.worker.userAgent).toBe('Mozilla/5.0 (worker realm)');
        expect(result.value.worker.hardwareConcurrency).toBe(64);
        expect(result.value.window.userAgent).toBe(navigator.userAgent);
        expect(result.value.window.engine).toBe('v8');
    });

    it('creates a CLASSIC worker in a production build: Firefox 111-113 have no module workers and the chunk is an IIFE', async () => {
        vi.stubEnv('DEV', false);
        installFakeWorker((worker) => worker.reply({ kind: SCOPE_REPLY_KIND, snapshot: workerSideSnapshot() }));

        const result = await workerScope();

        expect(result.state).toBe('ok');
        const [worker] = FakeWorker.instances;
        expect(worker?.url).toMatch(/scope\.worker/);
        // No `type` at all: a `{ type: 'module' }` here is what made Firefox 111-113 report `blocked`.
        expect(worker?.options).toBeUndefined();
    });

    it('reads the window snapshot AFTER the reply, not before the worker was asked', async () => {
        let stage = 'before';
        const spy = vi.spyOn(navigator, 'language', 'get').mockImplementation(() => stage);
        try {
            installFakeWorker((worker) => {
                stage = 'after';
                worker.reply({ kind: SCOPE_REPLY_KIND, snapshot: workerSideSnapshot() });
            });

            const result = await workerScope();
            expect(result.state === 'ok' && result.value.window.language).toBe('after');
        } finally {
            spy.mockRestore();
        }
    });

    it('re-types a hostile reply field by field before it reaches the claims', async () => {
        installFakeWorker((worker) =>
            worker.reply({ kind: SCOPE_REPLY_KIND, snapshot: { ...workerSideSnapshot(), platform: { toString: () => 'x' }, engine: 'chakra' } }),
        );

        const result = await workerScope();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.worker.platform).toBeNull();
        expect(result.value.worker.engine).toBe('unknown');
    });

    it('is unavailable (malformed), and terminates the worker, on a reply that is not the envelope', async () => {
        installFakeWorker((worker) => worker.reply({ hello: 'world' }));

        await expect(workerScope()).resolves.toEqual({ state: 'unavailable', reason: 'malformed' });
        expect(FakeWorker.instances[0]?.terminated).toBe(true);
    });

    it('is unavailable (malformed) on messageerror', async () => {
        installFakeWorker((worker) => worker.dispatchEvent(new Event('messageerror')));

        await expect(workerScope()).resolves.toEqual({ state: 'unavailable', reason: 'malformed' });
        expect(FakeWorker.instances[0]?.terminated).toBe(true);
    });

    it('is unavailable (blocked), terminates, and cancels the event, when the worker errors before replying', async () => {
        let event: Event | null = null;
        installFakeWorker((worker) => {
            event = new Event('error', { cancelable: true });
            worker.dispatchEvent(event);
        });

        await expect(workerScope()).resolves.toEqual({ state: 'unavailable', reason: 'blocked' });
        expect(FakeWorker.instances[0]?.terminated).toBe(true);
        expect((event as Event | null)?.defaultPrevented).toBe(true);
    });

    it('is unavailable (blocked) when the constructor throws (CSP, sandbox)', async () => {
        installFakeWorker(() => undefined);
        FakeWorker.throwOnConstruct = true;

        await expect(workerScope()).resolves.toEqual({ state: 'unavailable', reason: 'blocked' });
    });

    it('is unavailable (timeout) after WORKER_SCOPE_TIMEOUT_MS with no reply, and terminates the worker', async () => {
        vi.useFakeTimers();
        installFakeWorker(() => undefined); // never replies

        const pending = workerScope();
        await vi.advanceTimersByTimeAsync(WORKER_SCOPE_TIMEOUT_MS - 1);
        let settled = false;
        void pending.then(() => {
            settled = true;
        });
        await Promise.resolve();
        expect(settled).toBe(false);

        await vi.advanceTimersByTimeAsync(1);
        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'timeout' });
        expect(FakeWorker.instances[0]?.terminated).toBe(true);
    });

    it('is settled at once (released) and terminated by releaseShared() while waiting', async () => {
        installFakeWorker(() => undefined); // never replies

        const pending = workerScope();
        await Promise.resolve();
        releaseShared();

        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'released' });
        expect(FakeWorker.instances[0]?.terminated).toBe(true);
    });

    it('ignores a reply that arrives after the probe settled', async () => {
        vi.useFakeTimers();
        installFakeWorker(() => undefined);

        const pending = workerScope();
        await vi.advanceTimersByTimeAsync(WORKER_SCOPE_TIMEOUT_MS);
        const late = FakeWorker.instances[0] as FakeWorker;
        late.terminated = false; // a reply racing the terminate
        late.reply({ kind: SCOPE_REPLY_KIND, snapshot: workerSideSnapshot() });

        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'timeout' });
    });

    it('keeps the stable tier-2 claims identical across collections: elapsedMs is the only measured field', async () => {
        installFakeWorker((worker) => worker.reply({ kind: SCOPE_REPLY_KIND, snapshot: workerSideSnapshot() }));
        const challenge: Challenge = { token: 't', purpose: 'signin', expiresAt: 0 };
        const strip = (claims: unknown): string =>
            JSON.stringify(claims, (key, value) => (key === 'timing' || key === 'elapsedMs' ? undefined : value));

        const first = await collectTier2(challenge, 'signin');
        const second = await collectTier2(challenge, 'signin');

        const onWire = (first.claims.tier2 as Record<string, { workerType?: string }>).workerScope;
        expect(onWire?.workerType).toBe('dedicated');
        expect(strip(first.claims)).toBe(strip(second.claims));
        expect(first.digest).toBe(second.digest);
    });
});

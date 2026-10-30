/**
 * Fixes from the five-review round that are not covered by a probe's own suite:
 *
 * - `failed()` never throws, so a revoked Proxy or a throwing `name` getter thrown from a
 *   probe cannot escape `probe()`;
 * - a late `workerScope` reply, arriving after the probe settled, is ignored BEFORE anything
 *   is read, so it cannot recreate the shared WebGL context `releaseShared()` just lost;
 * - shared resources are held per collection (`acquireShared`), so one collection finishing
 *   does not release what another collection in flight is using.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { failed, probe, probeAsync } from '@device-id/collector/canonical';
import { collectTier2 } from '@device-id/collector/index';
import { SCOPE_REPLY_KIND, scopeSnapshot } from '@device-id/collector/realm';
import { acquireShared, onRelease, releaseShared } from '@device-id/collector/shared';
import { workerScope } from '@device-id/collector/value-probes';

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

describe('failed() never throws', () => {
    it('tags a revoked Proxy as a generic error instead of throwing from instanceof', () => {
        const { proxy, revoke } = Proxy.revocable({}, {});
        revoke();
        expect(() => failed(proxy)).not.toThrow();
        expect(failed(proxy)).toEqual({ state: 'error', name: 'Error' });
    });

    it('tags an error whose name getter throws as a generic error', () => {
        const hostile = new Error('x');
        Object.defineProperty(hostile, 'name', {
            get() {
                throw new TypeError('no name for you');
            },
        });
        expect(failed(hostile)).toEqual({ state: 'error', name: 'Error' });
    });

    it('so probe() and probeAsync() contain both, instead of letting them escape', async () => {
        const { proxy, revoke } = Proxy.revocable({}, {});
        revoke();
        expect(probe('revoked', () => {
            throw proxy;
        })).toEqual({ state: 'error', name: 'Error' });
        await expect(probeAsync('revoked', () => Promise.reject(proxy))).resolves.toEqual({ state: 'error', name: 'Error' });
    });

    it('still reports a normal error by its name', () => {
        expect(failed(new RangeError('r'))).toEqual({ state: 'error', name: 'RangeError' });
    });
});

describe('workerScope: a late reply touches nothing', () => {
    it('does not read the window snapshot (or ask for a WebGL context) after releaseShared() settled it', async () => {
        let worker: (EventTarget & { terminated: boolean }) | null = null;
        class SilentWorker extends EventTarget {
            terminated = false;
            constructor() {
                super();
                // eslint-disable-next-line @typescript-eslint/no-this-alias -- the test must reach the instance the probe created
                worker = this;
            }
            postMessage(): void {}
            terminate(): void {
                this.terminated = true;
            }
        }
        defineOwn(globalThis, 'Worker', SilentWorker);

        const webglRequests: string[] = [];
        const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
        const original = proto.getContext;
        proto.getContext = (kind: string): null => {
            webglRequests.push(kind);
            return null;
        };
        undos.push(() => {
            proto.getContext = original;
        });

        const pending = workerScope();
        await Promise.resolve();
        releaseShared();
        await expect(pending).resolves.toEqual({ state: 'unavailable', reason: 'released' });

        // The reply races the terminate and arrives anyway.
        const late = worker as unknown as EventTarget;
        late.dispatchEvent(new MessageEvent('message', { data: { kind: SCOPE_REPLY_KIND, snapshot: scopeSnapshot({ vendor: null, renderer: null }, null) } }));

        expect(webglRequests).toEqual([]);
    });
});

describe('shared resources are held per collection', () => {
    it('releases only when the last hold is let go, and a release function counts once', () => {
        const disposed: string[] = [];
        onRelease(() => disposed.push('resource'));

        const first = acquireShared();
        const second = acquireShared();
        first();
        first();
        expect(disposed).toEqual([]);

        second();
        expect(disposed).toEqual(['resource']);
    });

    it('collectTier2 does not release what another collection in flight is holding', async () => {
        const disposed: string[] = [];
        const otherCollection = acquireShared();
        onRelease(() => disposed.push('other collection’s worker'));

        await collectTier2({ token: 't', purpose: 'signin', expiresAt: 0 }, 'signin');
        expect(disposed).toEqual([]);

        otherCollection();
        expect(disposed).toEqual(['other collection’s worker']);
    });

    it('collectTier2 alone still releases at the end', async () => {
        const disposed: string[] = [];
        onRelease(() => disposed.push('released'));

        await collectTier2({ token: 't', purpose: 'signin', expiresAt: 0 }, 'signin');
        expect(disposed).toEqual(['released']);
    });

    it('a hard releaseShared() clears every hold, so a later collection is not blocked by a stale one', async () => {
        acquireShared(); // a collection that never let go (aborted)
        releaseShared();

        const disposed: string[] = [];
        onRelease(() => disposed.push('released'));
        await collectTier2({ token: 't', purpose: 'signin', expiresAt: 0 }, 'signin');
        expect(disposed).toEqual(['released']);
    });
});

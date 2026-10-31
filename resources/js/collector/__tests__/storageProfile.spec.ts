/**
 * `tier2.storageProfile`: the private-browsing evidence. The measured values of Chromium 153,
 * Firefox 155 and WebKit 26.6 are in the probe's docblock; here the probe's mapping from what the
 * browser answered to the wire value is pinned, including every way the APIs can fail.
 */
import { afterEach, describe, expect, it } from 'vitest';

import { PROBE_SET } from '@device-id/collector/protocol';
import { storageProfile, storageStep, TIER, VALUE_PROBES } from '@device-id/collector/value-probes';

const originalStorage = Object.getOwnPropertyDescriptor(navigator, 'storage');
const originalMemory = Object.getOwnPropertyDescriptor(performance, 'memory');

function stubStorage(storage: unknown): void {
    Object.defineProperty(navigator, 'storage', { value: storage, configurable: true });
}

function stubHeap(limit: number | undefined): void {
    Object.defineProperty(performance, 'memory', { value: limit === undefined ? undefined : { jsHeapSizeLimit: limit }, configurable: true });
}

afterEach(() => {
    if (originalStorage) Object.defineProperty(navigator, 'storage', originalStorage);
    else delete (navigator as unknown as Record<string, unknown>).storage;
    if (originalMemory) Object.defineProperty(performance, 'memory', originalMemory);
    else delete (performance as unknown as Record<string, unknown>).memory;
});

const GIB = 1024 ** 3;

describe('storageStep', () => {
    it('is half-octave steps of MiB, so 3 GiB and 10 GiB land far apart and a byte count is not sent', () => {
        expect(storageStep(3 * GIB)).toBe(23);
        expect(storageStep(10 * GIB)).toBe(27);
        expect(storageStep(1048576)).toBe(0);
    });

    it('is null for anything that is not a usable byte count', () => {
        for (const value of [undefined, null, NaN, Infinity, -5, 0, 1000, '10', {}]) expect(storageStep(value)).toBeNull();
    });
});

describe('storageProfile', () => {
    it('reads a Chromium incognito tab: a quota below the heap limit', async () => {
        stubStorage({ estimate: async () => ({ quota: 3 * GIB }), getDirectory: async () => ({}) });
        stubHeap(3.76e9);

        const result = await storageProfile();

        expect(result).toMatchObject({ state: 'ok', value: { quotaStep: 23, heapStep: 24, opfs: 'ok' } });
    });

    it('reads a normal profile: a quota well above the heap limit', async () => {
        stubStorage({ estimate: async () => ({ quota: 10 * GIB }), getDirectory: async () => ({}) });
        stubHeap(4.4e9);

        expect(await storageProfile()).toMatchObject({ value: { quotaStep: 27, heapStep: 24, opfs: 'ok' } });
    });

    it('classifies a Firefox private-browsing rejection as security and any other rejection as error', async () => {
        const security = Object.assign(new Error('denied'), { name: 'SecurityError' });
        const unknown = Object.assign(new Error('x'), { name: 'UnknownError' });
        stubHeap(undefined);

        stubStorage({ estimate: async () => ({ quota: 10 * GIB }), getDirectory: async () => { throw security; } });
        expect(await storageProfile()).toMatchObject({ value: { heapStep: null, opfs: 'security' } });

        stubStorage({ estimate: async () => ({ quota: 1000 * 1048576 }), getDirectory: async () => { throw unknown; } });
        expect(await storageProfile()).toMatchObject({ value: { opfs: 'error' } });
    });

    it('reports absence honestly when the APIs are missing or fail, and never throws', async () => {
        stubHeap(undefined);

        stubStorage(undefined);
        expect(await storageProfile()).toMatchObject({ state: 'ok', value: { quotaStep: null, heapStep: null, opfs: 'absent' } });

        stubStorage({ estimate: async () => { throw new Error('boom'); } });
        expect(await storageProfile()).toMatchObject({ value: { quotaStep: null, opfs: 'absent' } });
    });

    it('is a tier 2 probe of probe set 5 and sends no byte count', async () => {
        expect(PROBE_SET).toBeGreaterThanOrEqual(5);
        expect(VALUE_PROBES.find((entry) => entry.name === 'storageProfile')?.tier).toBe(TIER.TWO);

        stubStorage({ estimate: async () => ({ quota: 123456789012 }), getDirectory: async () => ({}) });
        stubHeap(4.4e9);
        const wire = JSON.stringify(await storageProfile());

        expect(wire).not.toContain('123456789012');
        expect(wire).not.toContain('4400000000');
    });
});

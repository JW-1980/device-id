/**
 * What the merge of the two former collectors added: the `webrtc` and `behavior` probes in the
 * registry, the behaviour listener lifecycle around a collection, `collectAndConfirm`, and the
 * host-chosen purpose.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { isBehaviorCollecting, resetBehaviorForTests } from '@device-id/collector/behavior';
import { collectAndConfirm, collectAndSend, collectAndSendDetailed, collectTier2 } from '@device-id/collector/index';
import { CORE_PROBES, FINGERPRINT_VERSION, PROBE_SET, type Challenge } from '@device-id/collector/protocol';
import { buildEnvelope } from '@device-id/collector/transport';
import { TIER, VALUE_PROBES } from '@device-id/collector/value-probes';

type Call = { url: string; body: any };

/** A `fetch` that answers the challenge endpoint with `challenge` and every claims POST with `claimsStatus`. */
function installFetch(options: { challenge?: Record<string, unknown> | null; claimsStatus?: number } = {}): { calls: Call[]; undo: () => void } {
    const calls: Call[] = [];
    const original = globalThis.fetch;
    const challenge = options.challenge === undefined ? { token: 'issued-token', purpose: 'signin', expires_at: 0 } : options.challenge;

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push({ url, body: typeof init?.body === 'string' ? JSON.parse(init.body) : null });
        if (url.endsWith('/challenge')) {
            return challenge === null
                ? new Response('', { status: 503 })
                : new Response(JSON.stringify(challenge), { status: 200, headers: { 'content-type': 'application/json' } });
        }

        return new Response('{"ok":true}', { status: options.claimsStatus ?? 200 });
    }) as typeof fetch;

    return {
        calls,
        undo: () => {
            globalThis.fetch = original;
        },
    };
}

const CHALLENGE: Challenge = { token: 'test-token-not-a-real-secret', purpose: 'signin', expiresAt: 0 };

describe('the merged probe registry', () => {
    it('registers webrtc and behavior in tier 2, switchable (not core)', () => {
        for (const name of ['webrtc', 'behavior']) {
            const entry = VALUE_PROBES.find((probe) => probe.name === name);
            expect(entry?.tier, name).toBe(TIER.TWO);
            expect(CORE_PROBES, name).not.toContain(name);
        }
    });

    it('registers behavior as a late probe: its snapshot is taken after the other deferred probes', () => {
        expect(VALUE_PROBES.find((probe) => probe.name === 'behavior')?.late).toBe(true);
    });

    it('keeps stackDepth out: a V8 constant, removed on purpose', () => {
        expect(VALUE_PROBES.map((probe) => probe.name)).not.toContain('stackDepth');
    });

    it('has unique probe names', () => {
        const names = VALUE_PROBES.map((probe) => probe.name);
        expect(new Set(names).size).toBe(names.length);
    });

    it('reports probe set 3 on the wire, next to envelope version 3', () => {
        const envelope = buildEnvelope({ challenge: CHALLENGE, slot: 'tier2', digest: '', claims: {} as never });
        expect(envelope.probes).toBe(PROBE_SET);
        expect(PROBE_SET).toBe(5);
        expect(envelope.v).toBe(FINGERPRINT_VERSION);
        expect(FINGERPRINT_VERSION).toBe(3);
    });

    it('collects webrtc and behavior in the tier-2 envelope, and omits both when the policy disables them', async () => {
        const on = await collectTier2(CHALLENGE, 'signin');
        expect(on.claims.tier2).toHaveProperty('webrtc');
        expect(on.claims.tier2).toHaveProperty('behavior');

        const off = await collectTier2({ ...CHALLENGE, disabledProbes: ['webrtc', 'behavior'] }, 'signin');
        expect(off.claims.tier2).not.toHaveProperty('webrtc');
        expect(off.claims.tier2).not.toHaveProperty('behavior');
        // Other probes still run.
        expect(off.claims.tier2).toHaveProperty('fontMetrics');
    }, 20_000);
});

describe('the behaviour listener lifecycle around a collection', () => {
    beforeEach(() => resetBehaviorForTests());
    afterEach(() => resetBehaviorForTests());

    it('listens from before the challenge, reports what happened in the tier-2 envelope, and stops afterwards', async () => {
        const recorder = installFetch();
        try {
            const outcome = await collectAndSendDetailed('signin', '/challenge', '/claims');
            expect(outcome.status).toBe('sent');
            expect(isBehaviorCollecting()).toBe(true);

            window.dispatchEvent(new KeyboardEvent('keydown', { code: 'KeyA' }));
            window.dispatchEvent(new MouseEvent('pointerdown'));

            if (outcome.status !== 'sent') return;
            const tier2 = await outcome.tier2;
            expect(tier2.send?.sent).toBe(true);

            const body = recorder.calls.filter((call) => call.url === '/claims')[1]?.body;
            expect(body.slot).toBe('tier2');
            expect(body.claims.tier2.behavior.keyboard.down).toBe(1);
            expect(body.claims.tier2.behavior.pointer.downs).toBe(1);
            expect(isBehaviorCollecting()).toBe(false);
        } finally {
            recorder.undo();
        }
    }, 20_000);

    it('does not listen, and sends no behavior, when the challenge policy disables it', async () => {
        const recorder = installFetch({ challenge: { token: 'issued-token', purpose: 'signin', expires_at: 0, disabled_probes: ['behavior'] } });
        try {
            const outcome = await collectAndSendDetailed('signin', '/challenge', '/claims');
            expect(outcome.status).toBe('sent');
            expect(isBehaviorCollecting()).toBe(false);

            if (outcome.status !== 'sent') return;
            await outcome.tier2;
            const body = recorder.calls.filter((call) => call.url === '/claims')[1]?.body;
            expect(body.claims.tier2).not.toHaveProperty('behavior');
        } finally {
            recorder.undo();
        }
    }, 20_000);

    it('leaves no listener behind when no challenge was issued', async () => {
        const recorder = installFetch({ challenge: null });
        try {
            expect((await collectAndSendDetailed('signin', '/challenge', '/claims')).status).toBe('no-challenge');
            expect(isBehaviorCollecting()).toBe(false);
        } finally {
            recorder.undo();
        }
    });

    it('reports "no-interaction" when the visitor did nothing, never a default that could hash as a device', async () => {
        const recorder = installFetch();
        try {
            const outcome = await collectAndSendDetailed('signin', '/challenge', '/claims');
            if (outcome.status !== 'sent') throw new Error(outcome.status);
            await outcome.tier2;

            const body = recorder.calls.filter((call) => call.url === '/claims')[1]?.body;
            expect(body.claims.tier2.behavior).toEqual({ state: 'unavailable' });
        } finally {
            recorder.undo();
        }
    }, 20_000);
});

describe('purposes and endpoints are the host\'s', () => {
    it('sends any purpose string the host chooses to the host\'s challenge URL, and the envelopes to its claims URL', async () => {
        const recorder = installFetch();
        try {
            const result = await collectAndSend('vote', '/host/challenge', '/host/claims');
            expect(result).not.toBeNull();

            expect(recorder.calls[0]).toEqual({ url: '/host/challenge', body: { purpose: 'vote' } });
            expect(recorder.calls[1]?.url).toBe('/host/claims');
            expect(recorder.calls[1]?.body.claims.purpose).toBe('vote');
        } finally {
            recorder.undo();
        }
    });
});

describe('collectAndConfirm', () => {
    afterEach(() => resetBehaviorForTests());

    it('resolves true only once the tier-1 claims were answered 2xx', async () => {
        const recorder = installFetch({ claimsStatus: 200 });
        try {
            expect(await collectAndConfirm('vote', '/challenge', '/claims')).toBe(true);
            expect(recorder.calls[0]?.body).toEqual({ purpose: 'vote' });
            expect(recorder.calls[1]?.body.slot).toBe('tier1');
        } finally {
            recorder.undo();
        }
    });

    it('resolves false when the server refuses the claims', async () => {
        const recorder = installFetch({ claimsStatus: 403 });
        try {
            expect(await collectAndConfirm('vote', '/challenge', '/claims')).toBe(false);
        } finally {
            recorder.undo();
        }
    });

    it('resolves false, without sending claims, when no challenge is issued', async () => {
        const recorder = installFetch({ challenge: null });
        try {
            expect(await collectAndConfirm('vote', '/challenge', '/claims')).toBe(false);
            expect(recorder.calls.map((call) => call.url)).toEqual(['/challenge']);
        } finally {
            recorder.undo();
        }
    });
});

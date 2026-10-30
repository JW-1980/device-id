/**
 * The tier-2 envelope is posted only after the tier-1 envelope was ANSWERED 2xx
 * (round-2 R2-08 / BE2-10): a tier-2 envelope that overtook its tier-1 envelope found no
 * observation to attach to, and spent the token's tier-2 slot on a refusal. `sendClaims`
 * therefore reports, besides whether the request was started (round 4), a `delivered` promise
 * with the server's answer, and `scheduleTier2` waits for it.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { collectAndSend, collectAndSendDetailed, reportDeclined, scheduleTier2 } from '@device-id/v3/index';
import { sendClaims, sendDecline } from '@device-id/v3/transport';
import type { Challenge } from '@device-id/v3/protocol';

const CHALLENGE: Challenge = { token: 'issued-token', purpose: 'signin', expiresAt: Date.now() + 300_000 };

interface Recorded {
    url: string;
    slot: string | undefined;
    startedAt: number;
    answeredAt: number | undefined;
}

/**
 * A fake `fetch` that answers the tier-1 claims POST after `tier1DelayMs` with
 * `tier1Status`, records when every request started and was answered, and answers
 * everything else at once.
 */
function installFetch(tier1Status: number, tier1DelayMs: number): { calls: Recorded[]; undo: () => void } {
    const calls: Recorded[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as { slot?: string; purpose?: string }) : {};
        const record: Recorded = { url, slot: body.slot, startedAt: Date.now(), answeredAt: undefined };
        calls.push(record);
        if (url.endsWith('/challenge')) {
            record.answeredAt = Date.now();
            return new Response(JSON.stringify({ token: 'issued-token', purpose: 'signin', expires_at: 0 }), { status: 200 });
        }
        if (body.slot === 'tier1') {
            await new Promise((r) => setTimeout(r, tier1DelayMs));
            record.answeredAt = Date.now();
            return new Response('', { status: tier1Status });
        }
        record.answeredAt = Date.now();
        return new Response('{"ok":true}', { status: 200 });
    }) as typeof fetch;

    return {
        calls,
        undo: () => {
            globalThis.fetch = original;
        },
    };
}

afterEach(() => {
    vi.restoreAllMocks();
});

describe('sendClaims / sendDecline: `delivered` resolves with the server’s answer', () => {
    it('true on 2xx, false on a refusal, false on a network error, false when not started', async () => {
        const okFetch = installFetch(200, 0);
        try {
            await expect(sendClaims('/claims', { challenge: CHALLENGE, slot: 'tier1', digest: '', claims: { v: 3, purpose: 'signin', integrity: { findings: [], data: {}, elapsedMs: 0 }, tier1: {}, timing: { elapsedMs: 0, budgetMs: 0, tier2Skipped: false } } }).delivered).resolves.toBe(true);
            await expect(sendDecline('/claims', CHALLENGE, 'blocked').delivered).resolves.toBe(true);
        } finally {
            okFetch.undo();
        }

        const refused = installFetch(413, 0);
        try {
            await expect(sendClaims('/claims', { challenge: CHALLENGE, slot: 'tier1', digest: '', claims: { v: 3, purpose: 'signin', integrity: { findings: [], data: {}, elapsedMs: 0 }, tier1: {}, timing: { elapsedMs: 0, budgetMs: 0, tier2Skipped: false } } }).delivered).resolves.toBe(false);
        } finally {
            refused.undo();
        }

        const original = globalThis.fetch;
        globalThis.fetch = (async () => {
            throw new TypeError('network down');
        }) as typeof fetch;
        try {
            await expect(sendDecline('/claims', CHALLENGE, 'blocked').delivered).resolves.toBe(false);
        } finally {
            globalThis.fetch = original;
        }

        const padded = { v: 3, purpose: 'signin' as const, integrity: { findings: [], data: {}, elapsedMs: 0 }, tier1: { pad: '€'.repeat(9000) }, timing: { elapsedMs: 0, budgetMs: 0, tier2Skipped: false } };
        const noFetch = installFetch(200, 0);
        try {
            await expect(sendClaims('/claims', { challenge: CHALLENGE, slot: 'tier1', digest: '', claims: padded }).delivered).resolves.toBe(false);
            expect(noFetch.calls).toHaveLength(0);
        } finally {
            noFetch.undo();
        }
    });

    it('starts the request synchronously, before anyone awaits the promise', () => {
        const recorder = installFetch(200, 0);
        try {
            void sendClaims('/claims', { challenge: CHALLENGE, slot: 'tier1', digest: '', claims: { v: 3, purpose: 'signin', integrity: { findings: [], data: {}, elapsedMs: 0 }, tier1: {}, timing: { elapsedMs: 0, budgetMs: 0, tier2Skipped: false } } });
            expect(recorder.calls).toHaveLength(1);
        } finally {
            recorder.undo();
        }
    });
});

describe('collectAndSend orders the two envelopes', () => {
    it('posts tier 2 only after the tier-1 response arrived, under the same nonce', async () => {
        const recorder = installFetch(200, 250);
        try {
            const result = await collectAndSend('signin', '/challenge', '/claims');
            expect(result?.slot).toBe('tier1');

            await vi.waitFor(() => expect(recorder.calls.filter((c) => c.url === '/claims')).toHaveLength(2), { timeout: 8000 });
            const [tier1, tier2] = recorder.calls.filter((c) => c.url === '/claims');
            expect(tier1?.slot).toBe('tier1');
            expect(tier2?.slot).toBe('tier2');
            expect(tier1?.answeredAt).toBeDefined();
            expect(tier2!.startedAt).toBeGreaterThanOrEqual(tier1!.answeredAt as number);
        } finally {
            recorder.undo();
        }
    });

    it('does not post tier 2 at all when the tier-1 envelope was refused', async () => {
        const recorder = installFetch(413, 0);
        try {
            const result = await collectAndSend('signin', '/challenge', '/claims');
            expect(result?.slot).toBe('tier1');

            // Give the schedule more than enough time to have collected and posted tier 2.
            await new Promise((r) => setTimeout(r, 1500));
            const claims = recorder.calls.filter((c) => c.url === '/claims');
            expect(claims.map((c) => c.slot)).toEqual(['tier1']);
        } finally {
            recorder.undo();
        }
    });

    it('scheduleTier2 still resolves with the collected result when the tier-1 promise says no', async () => {
        const recorder = installFetch(200, 0);
        try {
            const result = await scheduleTier2(CHALLENGE, 'signin', undefined, '/claims', Promise.resolve(false));
            expect(result?.slot).toBe('tier2');
            expect(recorder.calls).toHaveLength(0);
        } finally {
            recorder.undo();
        }
    });

    it('collectAndSendDetailed says the tier-2 envelope was held back because tier 1 was refused', async () => {
        const recorder = installFetch(413, 0);
        try {
            const outcome = await collectAndSendDetailed('signin', '/challenge', '/claims');
            expect(outcome.status).toBe('sent');
            if (outcome.status !== 'sent') return;
            await expect(outcome.send.delivered).resolves.toBe(false);

            const tier2 = await outcome.tier2;
            expect(tier2.result?.slot).toBe('tier2');
            expect(tier2.tier1Delivered).toBe(false);
            expect(tier2.send).toBeNull();
            expect(recorder.calls.filter((c) => c.url === '/claims').map((c) => c.slot)).toEqual(['tier1']);
        } finally {
            recorder.undo();
        }
    });

    it('reportDeclined resolves with the server’s answer', async () => {
        const recorder = installFetch(200, 0);
        try {
            await expect(reportDeclined('/claims', 'blocked', '/challenge', 'signin', CHALLENGE)).resolves.toBe(true);
            expect(recorder.calls.map((c) => c.url)).toEqual(['/claims']);
        } finally {
            recorder.undo();
        }
    });
});

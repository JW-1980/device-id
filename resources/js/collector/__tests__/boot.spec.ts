/**
 * The boot entry for pages without a single-page application: `data-fingerprint-*` attributes
 * on <body> (or explicit options) start the collection once per tab per purpose.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { resetBehaviorForTests } from '@device-id/collector/behavior';
import { BOOT_MARKER_PREFIX, initFingerprint } from '@device-id/collector/boot';

type Call = { url: string; body: any };

function installFetch(handler: (url: string) => Response | Promise<Response>): { calls: Call[]; undo: () => void } {
    const calls: Call[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push({ url, body: typeof init?.body === 'string' ? JSON.parse(init.body) : null });

        return handler(url);
    }) as typeof fetch;

    return {
        calls,
        undo: () => {
            globalThis.fetch = original;
        },
    };
}

const ok = (): Response => new Response(JSON.stringify({ token: 'issued-token', purpose: 'signin', expires_at: 0 }), { status: 200, headers: { 'content-type': 'application/json' } });

const answerEverything = (url: string): Response => (url.endsWith('challenge') ? ok() : new Response('{"ok":true}', { status: 200 }));

function setBody(attributes: Record<string, string>): void {
    for (const key of Object.keys(document.body.dataset)) {
        delete document.body.dataset[key];
    }
    for (const [key, value] of Object.entries(attributes)) {
        document.body.dataset[key] = value;
    }
}

describe('initFingerprint', () => {
    beforeEach(() => {
        sessionStorage.clear();
        setBody({});
    });
    afterEach(() => {
        resetBehaviorForTests();
        sessionStorage.clear();
        setBody({});
        vi.restoreAllMocks();
    });

    it('does nothing, and asks the server for nothing, on a page without a purpose', async () => {
        const recorder = installFetch(answerEverything);
        try {
            expect(await initFingerprint()).toBeNull();
            expect(recorder.calls).toEqual([]);
            expect(sessionStorage.length).toBe(0);
        } finally {
            recorder.undo();
        }
    });

    it('reads purpose and both URLs from the body attributes', async () => {
        setBody({
            fingerprintPurpose: 'register',
            fingerprintChallengeUrl: '/wz/challenge',
            fingerprintClaimsUrl: '/wz/claims',
        });
        const recorder = installFetch(answerEverything);
        try {
            const outcome = await initFingerprint();

            expect(outcome?.status).toBe('sent');
            expect(recorder.calls[0]).toEqual({ url: '/wz/challenge', body: { purpose: 'register' } });
            expect(recorder.calls[1]?.url).toBe('/wz/claims');
            expect(recorder.calls[1]?.body.claims.purpose).toBe('register');
        } finally {
            recorder.undo();
        }
    });

    it('uses the collector\'s default endpoints when the page names none', async () => {
        setBody({ fingerprintPurpose: 'signin' });
        const recorder = installFetch(answerEverything);
        try {
            await initFingerprint();

            expect(recorder.calls[0]?.url).toBe('/security/fingerprint/challenge');
            expect(recorder.calls[1]?.url).toBe('/security/fingerprint/claims');
        } finally {
            recorder.undo();
        }
    });

    it('lets explicit options win over the attributes', async () => {
        setBody({ fingerprintPurpose: 'signin', fingerprintChallengeUrl: '/attr/challenge', fingerprintClaimsUrl: '/attr/claims' });
        const recorder = installFetch(answerEverything);
        try {
            await initFingerprint({ purpose: 'checkout', challengeUrl: '/opt/challenge', claimsUrl: '/opt/claims' });

            expect(recorder.calls[0]).toEqual({ url: '/opt/challenge', body: { purpose: 'checkout' } });
            expect(recorder.calls[1]?.url).toBe('/opt/claims');
        } finally {
            recorder.undo();
        }
    });

    it('reports once per tab per purpose, but separately for another purpose', async () => {
        setBody({ fingerprintPurpose: 'signin' });
        const recorder = installFetch(answerEverything);
        try {
            expect((await initFingerprint())?.status).toBe('sent');
            const callsAfterFirst = recorder.calls.length;
            expect(await initFingerprint()).toBeNull();
            expect(recorder.calls).toHaveLength(callsAfterFirst);
            expect(sessionStorage.getItem(`${BOOT_MARKER_PREFIX}signin`)).toBe('1');

            expect((await initFingerprint({ purpose: 'register' }))?.status).toBe('sent');
        } finally {
            recorder.undo();
        }
    });

    it('still collects, once per navigation, where sessionStorage is blocked', async () => {
        setBody({ fingerprintPurpose: 'signin' });
        vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
            throw new DOMException('blocked', 'SecurityError');
        });
        vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
            throw new DOMException('blocked', 'SecurityError');
        });
        const recorder = installFetch(answerEverything);
        try {
            expect((await initFingerprint())?.status).toBe('sent');
            expect((await initFingerprint())?.status).toBe('sent');
        } finally {
            recorder.undo();
        }
    });

    it('forgets the marker after a failure that may pass, so the next page load tries again', async () => {
        setBody({ fingerprintPurpose: 'signin' });
        const network = installFetch(() => {
            throw new TypeError('network down');
        });
        try {
            expect((await initFingerprint())?.status).toBe('no-challenge');
            expect(sessionStorage.getItem(`${BOOT_MARKER_PREFIX}signin`)).toBeNull();
        } finally {
            network.undo();
        }

        const unavailable = installFetch(() => new Response('', { status: 503 }));
        try {
            expect((await initFingerprint())?.status).toBe('no-challenge');
            expect(sessionStorage.getItem(`${BOOT_MARKER_PREFIX}signin`)).toBeNull();
        } finally {
            unavailable.undo();
        }

        const recovered = installFetch(answerEverything);
        try {
            expect((await initFingerprint())?.status).toBe('sent');
        } finally {
            recovered.undo();
        }
    });

    it('keeps the marker when the server refused the challenge (a retry would be refused again)', async () => {
        setBody({ fingerprintPurpose: 'signin' });
        const recorder = installFetch(() => new Response('', { status: 429 }));
        try {
            expect((await initFingerprint())?.status).toBe('no-challenge');
            expect(sessionStorage.getItem(`${BOOT_MARKER_PREFIX}signin`)).toBe('1');
            expect(await initFingerprint()).toBeNull();
            expect(recorder.calls).toHaveLength(1);
        } finally {
            recorder.undo();
        }
    });
});

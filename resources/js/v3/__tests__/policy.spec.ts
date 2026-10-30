/**
 * The method policy (CONTRACT-2 §P): the server's list of disabled probes, delivered as
 * `disabled_probes` in the challenge response or as `<meta name="nc-fingerprint-disabled">`,
 * and applied by `collect`, `collectTier2`, `collectForIdentity` and `collectAndSend`.
 *
 * The contract under test: a disabled probe is ABSENT from the claims (not `unavailable`);
 * core probes and unknown names are ignored; a malformed policy means "run everything"; the
 * policy is never echoed into the claims.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { CORE_PROBES, effectiveDisabled, type Challenge } from '@device-id/v3/protocol';
import { collect, collectAndSend, collectForIdentity, collectTier2, fetchChallenge, readDisabledMeta, DISABLED_META_NAME } from '@device-id/v3/index';
import { enabledProbesOf, probesOf, TIER, VALUE_PROBES } from '@device-id/v3/value-probes';
import { collectDeferredIntegrity, collectIntegrity } from '@device-id/v3/integrity';

const challenge = (disabledProbes?: readonly string[]): Challenge => ({ token: 't', purpose: 'signin', expiresAt: 0, disabledProbes });

const undos: Array<() => void> = [];
afterEach(() => {
    while (undos.length) undos.pop()?.();
});

function installMeta(content: string | null): void {
    const meta = document.createElement('meta');
    meta.setAttribute('name', DISABLED_META_NAME);
    if (content !== null) meta.setAttribute('content', content);
    document.head.appendChild(meta);
    undos.push(() => meta.remove());
}

describe('effectiveDisabled', () => {
    it('treats anything but an array as no policy', () => {
        for (const value of [undefined, null, 'voices', 42, { voices: true }]) {
            expect(effectiveDisabled(value)).toEqual([]);
        }
    });

    it('keeps trimmed, de-duplicated strings and drops non-strings and empties', () => {
        expect(effectiveDisabled([' voices ', 'voices', 7, null, '', '  ', 'workerScope'])).toEqual(['voices', 'workerScope']);
    });

    it('never lets a core probe through, whatever the list says', () => {
        expect(effectiveDisabled([...CORE_PROBES, 'voices'])).toEqual(['voices']);
    });

    it('keeps unknown names (a newer server), which then match nothing', () => {
        expect(effectiveDisabled(['probeFromTheFuture'])).toEqual(['probeFromTheFuture']);
        expect(enabledProbesOf(TIER.TWO, ['probeFromTheFuture']).map((p) => p.name)).toEqual(probesOf(TIER.TWO).map((p) => p.name));
    });

    it('lists exactly the CONTRACT-2 §N core names', () => {
        expect([...CORE_PROBES].sort()).toEqual([
            'architecture', 'audioHardware', 'audioRealtime', 'codecs', 'cssMedia', 'dateParsing', 'descriptorIntegrity',
            'engineIdentity', 'environment', 'esFeatures', 'objectShape', 'removedApiBoundary', 'resistance', 'uaClientHints',
            'wrongReceiver',
        ]);
    });

    it('every core value probe exists in the registry under that exact name', () => {
        const names = VALUE_PROBES.map((entry) => entry.name);
        for (const core of CORE_PROBES.filter((name) => !['wrongReceiver', 'descriptorIntegrity', 'resistance'].includes(name))) {
            expect(names).toContain(core);
        }
    });
});

describe('enabledProbesOf', () => {
    it('removes the named probes and keeps registry order', () => {
        const names = enabledProbesOf(TIER.HARDWARE, ['voices', 'gpu']).map((p) => p.name);
        expect(names).toEqual(probesOf(TIER.HARDWARE).map((p) => p.name).filter((n) => n !== 'voices' && n !== 'gpu'));
    });

    it('runs a core probe even when it is named directly (defence in depth)', () => {
        expect(enabledProbesOf(TIER.ONE, ['environment', 'engineIdentity']).map((p) => p.name)).toContain('environment');
        // `engineIdentity` is core since round 4 (security F4), so it runs whatever the policy says.
        expect(enabledProbesOf(TIER.ONE, ['environment', 'engineIdentity']).map((p) => p.name)).toContain('engineIdentity');
        expect(enabledProbesOf(TIER.TWO, ['voices', 'audioRealtime']).map((p) => p.name)).not.toContain('voices');
    });
});

describe('readDisabledMeta', () => {
    it('is empty when the tag is absent, empty, or has no content', () => {
        expect(readDisabledMeta()).toEqual([]);
        installMeta('');
        expect(readDisabledMeta()).toEqual([]);
        undos.pop()?.();
        installMeta(null);
        expect(readDisabledMeta()).toEqual([]);
    });

    it('splits on commas, trims, and drops core names', () => {
        installMeta(' voices, workerScope,,environment ,canvasFill');
        expect(readDisabledMeta()).toEqual(['voices', 'workerScope', 'canvasFill']);
    });
});

describe('collect (tier 1 + integrity)', () => {
    it('keeps every tier-1 probe: all of them are core since `engineIdentity` became one (round 4)', async () => {
        // Naming a core probe in a policy must not remove it.
        const result = await collect(challenge(['engineIdentity']), 'signin');

        expect(result.claims.tier1).toHaveProperty('engineIdentity');
        expect(result.claims.tier1).toHaveProperty('architecture');
        expect(Object.keys(result.claims.tier1)).toHaveLength(probesOf(TIER.ONE).length);
    });

    it('runs core probes and ignores unknown names', async () => {
        const all = await collect(challenge(), 'signin');
        const result = await collect(challenge(['environment', 'dateParsing', 'noSuchProbe']), 'signin');

        expect(Object.keys(result.claims.tier1).sort()).toEqual(Object.keys(all.claims.tier1).sort());
    });

    it('skips disabled integrity probes and keeps the core ones', async () => {
        const result = await collect(challenge(['domBlockers', 'canvasFill', 'mathDual', 'wrongReceiver', 'descriptorIntegrity']), 'signin');
        const data = result.claims.integrity.data;

        expect(data).not.toHaveProperty('domBlockers');
        expect(data).not.toHaveProperty('canvasFill');
        expect(data).not.toHaveProperty('mathDual');
        expect(data).toHaveProperty('wrongReceiver');
        expect(data).toHaveProperty('descriptorIntegrity');
        expect(data).toHaveProperty('canvasDual');
    });

    it('does not echo the policy into the claims, and a different policy is a different digest', async () => {
        const off = await collect(challenge(['domBlockers']), 'signin');
        const on = await collect(challenge(), 'signin');

        expect(JSON.stringify(off.claims)).not.toMatch(/disabled|policy/i);
        expect(off.digest).not.toBe(on.digest);
    });

    it('treats a malformed policy on the challenge as no policy', async () => {
        const result = await collect({ ...challenge(), disabledProbes: 'domBlockers' as unknown as string[] }, 'signin');
        expect(result.claims.integrity.data).toHaveProperty('domBlockers');
    });
});

describe('collectTier2', () => {
    it('leaves disabled tier-2 and hardware probes out of the tier2 block', async () => {
        const result = await collectTier2(challenge(['voices', 'workerScope', 'audioHardware']), 'signin');
        const tier2 = result.claims.tier2 ?? {};

        expect(tier2).not.toHaveProperty('voices');
        expect(tier2).not.toHaveProperty('workerScope');
        // audioHardware is core: still collected.
        expect(tier2).toHaveProperty('audioHardware');
        expect(tier2).toHaveProperty('intl');
        expect(tier2).toHaveProperty('fontMetrics');
    });
});

describe('collectForIdentity', () => {
    it('reads its policy from the meta tag by default', async () => {
        installMeta('voices,workerScope,engineIdentity,canvasFill,environment');

        const claims = await collectForIdentity(5000);

        expect(claims.tier1).toHaveProperty('engineIdentity');
        expect(claims.tier1).toHaveProperty('environment');
        expect(claims.tier2).not.toHaveProperty('voices');
        expect(claims.tier2).not.toHaveProperty('workerScope');
        expect(claims.tier2).toHaveProperty('intl');
        expect(claims.integrity.data).not.toHaveProperty('canvasFill');
    });

    it('takes an explicit policy over the meta tag, sanitised the same way', async () => {
        installMeta('voices');

        const claims = await collectForIdentity(5000, ['workerScope', 'engineIdentity', 'environment']);

        expect(claims.tier2).not.toHaveProperty('workerScope');
        expect(claims.tier1).toHaveProperty('engineIdentity');
        expect(claims.tier1).toHaveProperty('environment');
        expect(claims.tier2).toHaveProperty('voices');
    });
});

describe('collectAndSend', () => {
    function installFetch(challengeBody: Record<string, unknown>): Array<{ url: string; body: Record<string, unknown> | null }> {
        const calls: Array<{ url: string; body: Record<string, unknown> | null }> = [];
        const original = globalThis.fetch;
        globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            calls.push({ url, body: typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : null });
            if (url.endsWith('/challenge')) {
                return new Response(JSON.stringify({ token: 'policy-token', purpose: 'signin', expires_at: 0, ...challengeBody }), { status: 200 });
            }
            return new Response('{"ok":true}', { status: 200 });
        }) as typeof fetch;
        undos.push(() => {
            globalThis.fetch = original;
        });
        return calls;
    }

    const envelopes = (calls: Array<{ url: string; body: Record<string, unknown> | null }>) =>
        calls.filter((c) => c.url === '/claims').map((c) => c.body?.claims as { tier1: Record<string, unknown>; tier2?: Record<string, unknown>; integrity: { data: Record<string, unknown> } });

    it('applies disabled_probes from the challenge to BOTH posted envelopes', async () => {
        const calls = installFetch({ disabled_probes: ['voices', 'workerScope', 'engineIdentity', 'domBlockers'] });

        await collectAndSend('signin', '/challenge', '/claims');
        await vi.waitFor(() => expect(envelopes(calls)).toHaveLength(2), { timeout: 5000 });

        const [tier1, tier2] = envelopes(calls);
        expect(tier1?.tier1).toHaveProperty('engineIdentity');
        expect(tier1?.tier1).toHaveProperty('environment');
        expect(tier1?.integrity.data).not.toHaveProperty('domBlockers');
        expect(tier2?.tier2).not.toHaveProperty('voices');
        expect(tier2?.tier2).not.toHaveProperty('workerScope');
        expect(tier2?.tier2).toHaveProperty('audioReadback');
        for (const call of calls) expect(JSON.stringify(call.body)).not.toMatch(/disabled/);
    });

    it('fetchChallenge maps expires_at and disabled_probes, and accepts an already camelCased response', async () => {
        installFetch({ expires_at: 1234, disabled_probes: ['voices', 'environment'] });
        expect(await fetchChallenge('/challenge', 'signin')).toEqual(expect.objectContaining({ token: 'policy-token', expiresAt: 1234, disabledProbes: ['voices'] }));
        undos.pop()?.();

        installFetch({ expires_at: undefined, expiresAt: 5678, disabledProbes: ['gpu'] });
        expect(await fetchChallenge('/challenge', 'signin')).toEqual(expect.objectContaining({ expiresAt: 5678, disabledProbes: ['gpu'] }));
    });

    it('runs everything when disabled_probes is malformed', async () => {
        const calls = installFetch({ disabled_probes: 'voices,workerScope' });

        await collectAndSend('signin', '/challenge', '/claims');
        await vi.waitFor(() => expect(envelopes(calls)).toHaveLength(2), { timeout: 5000 });

        expect(envelopes(calls)[1]?.tier2).toHaveProperty('voices');
        expect(envelopes(calls)[1]?.tier2).toHaveProperty('workerScope');
    });
});

describe('deferred integrity phase (CONTRACT-2 addendum)', () => {
    it('puts the deferred phase in the TIER-2 envelope, and phantomRealm/resistance are not in tier 1', async () => {
        const tier1 = await collect(challenge(), 'signin');
        const tier2 = await collectTier2(challenge(), 'signin');

        expect(Object.keys(tier2.claims.integrity.data).sort()).toEqual(['canvasFill', 'phantomRealm', 'resistance']);
        expect(Array.isArray(tier2.claims.integrity.findings)).toBe(true);
        expect(typeof tier2.claims.integrity.elapsedMs).toBe('number');
        expect(tier1.claims.integrity.data).not.toHaveProperty('phantomRealm');
        // `ok` reports the deferred phase's own findings, not a constant.
        expect(tier2.ok).toBe(tier2.claims.integrity.findings.length === 0);
    });

    it('applies the policy to the deferred phase too, but never to the core resistance', async () => {
        const tier2 = await collectTier2(challenge(['phantomRealm', 'canvasFill', 'resistance']), 'signin');

        expect(Object.keys(tier2.claims.integrity.data)).toEqual(['resistance']);
    });

    it('merges both phases on the identify path: findings concatenated, data merged, durations summed', async () => {
        const sync = collectIntegrity();
        const deferred = collectDeferredIntegrity();

        const claims = await collectForIdentity(5000, []);

        expect(claims.integrity.findings.map((f) => f.code)).toEqual([...sync.findings, ...deferred.findings].map((f) => f.code));
        expect(Object.keys(claims.integrity.data).sort()).toEqual([...new Set([...Object.keys(sync.data), ...Object.keys(deferred.data)])].sort());
        expect(claims.integrity.data).toHaveProperty('phantomRealm');
        expect(claims.integrity.data).toHaveProperty('wrongReceiver');
        expect(claims.integrity.elapsedMs).toBeGreaterThanOrEqual(0);
    });

    it('keeps the synchronous integrity alone when tier 2 times out on the identify path', async () => {
        const claims = await collectForIdentity(0, []);

        expect(claims.timing.tier2Skipped).toBe(true);
        expect(claims.integrity.data).not.toHaveProperty('phantomRealm');
        expect(claims.integrity.data).toHaveProperty('wrongReceiver');
    });

    describe('with a real deferred finding (a page-side toString hiding a patched Math.sin)', () => {
        function installToStringSpoof(): void {
            const originalSin = Math.sin;
            const originalToString = Function.prototype.toString;
            const fake = function sin(x: number): number {
                return originalSin(x);
            };
            Math.sin = fake;
            Function.prototype.toString = function (this: unknown): string {
                return this === fake ? 'function sin() { [native code] }' : originalToString.call(this);
            };
            undos.push(() => {
                Math.sin = originalSin;
                Function.prototype.toString = originalToString;
            });
        }

        it('reports the deferred finding in the tier-2 envelope, and the result is not ok', async () => {
            installToStringSpoof();

            const tier2 = await collectTier2(challenge(), 'signin');

            expect(tier2.claims.integrity.findings.map((f) => f.code)).toContain('realm_tostring_mismatch');
            expect(tier2.ok).toBe(false);
        });

        it('concatenates the deferred findings after the synchronous ones on the identify path', async () => {
            installToStringSpoof();
            const syncCodes = collectIntegrity().findings.map((f) => f.code);

            const claims = await collectForIdentity(5000, []);
            const codes = claims.integrity.findings.map((f) => f.code);

            expect(codes.slice(0, syncCodes.length)).toEqual(syncCodes);
            expect(codes.slice(syncCodes.length)).toContain('realm_tostring_mismatch');
        });
    });
});

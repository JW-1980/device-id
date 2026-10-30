/**
 * `collectForIdentity()` — the one claim set the identify path posts
 * (resources/js/utils/deviceIdentity.ts): both tiers merged, no purpose, no
 * challenge, nothing sent, and a bounded wait for the chunked tier 2.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { collectForIdentity, IDENTITY_TIER2_TIMEOUT_MS } from '@device-id/v3/index';
import { FINGERPRINT_VERSION } from '@device-id/v3/protocol';
import { TIER, probesOf } from '@device-id/v3/value-probes';

describe('collectForIdentity', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        vi.useRealTimers();
    });

    it('merges tier 1, tier 2 and the hardware probes into one claim set without a purpose', async () => {
        const fetchSpy = vi.spyOn(globalThis, 'fetch');

        const claims = await collectForIdentity();

        expect(claims.v).toBe(FINGERPRINT_VERSION);
        expect(Object.keys(claims).sort()).toEqual(['integrity', 'tier1', 'tier2', 'timing', 'v']);
        expect('purpose' in claims).toBe(false);
        expect(claims.timing.tier2Skipped).toBe(false);

        for (const entry of probesOf(TIER.ONE)) {
            expect(claims.tier1).toHaveProperty(entry.name);
        }
        for (const entry of [...probesOf(TIER.TWO), ...probesOf(TIER.HARDWARE)]) {
            expect(claims.tier2).toHaveProperty(entry.name);
        }

        // Nothing leaves the page: no challenge, no envelope.
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(IDENTITY_TIER2_TIMEOUT_MS).toBe(5000);
    });

    it('sends tier 1 alone, and says so, when NOTHING of tier 2 settled inside the cap', async () => {
        // An idle callback that never fires: the deferred schedule cannot start.
        vi.stubGlobal('requestIdleCallback', () => 0);

        const claims = await collectForIdentity(20);

        expect(claims.tier2).toBeUndefined();
        expect(claims.timing.tier2Skipped).toBe(true);
        expect(Object.keys(claims.tier1).length).toBeGreaterThan(0);

        vi.unstubAllGlobals();
    });
});

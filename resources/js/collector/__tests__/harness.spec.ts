/**
 * The harness-only measurement module (notes/24 finding F6, recommendation R5).
 *
 * `measureTierOne` and `describeCanonical` had no production consumer, yet shipped in the
 * collector chunk under readable export names. They now live in `harness.ts`, which only
 * tests/Browser/transport-checks.mjs bundles. The harness separately asserts that the BUILT
 * chunk does not export them; this spec pins the source side of the same contract.
 */

import { describe, expect, it } from 'vitest';
import * as collector from '@device-id/collector/index';
import { canonicalise } from '@device-id/collector/canonical';
import { describeCanonical, measureTierOne } from '@device-id/collector/harness';
import { probesOf, TIER } from '@device-id/collector/value-probes';

describe('harness-only measurement helpers', () => {
    it('are not exported by the production entry, which keeps the two the admin demo uses', () => {
        const surface = Object.keys(collector);

        expect(surface).not.toContain('measureTierOne');
        expect(surface).not.toContain('describeCanonical');
        // Pages/Admin/Security/FingerprintDemo.vue calls these in production.
        expect(surface).toContain('measureProbes');
        expect(surface).toContain('measurePhases');
    });

    it('measureTierOne times exactly the tier-1 probes, each with its state and a duration', async () => {
        const rows = await measureTierOne();

        expect(rows.map((row) => row.name).sort()).toEqual(probesOf(TIER.ONE).map((entry) => entry.name).sort());
        for (const row of rows) {
            expect(['ok', 'unavailable', 'error']).toContain(row.state);
            expect(Number.isFinite(row.ms)).toBe(true);
            expect(row.ms).toBeGreaterThanOrEqual(0);
        }
    });

    it('describeCanonical is the digest canonicaliser: key order does not matter, values do', () => {
        expect(describeCanonical).toBe(canonicalise);
        expect(describeCanonical({ b: 1, a: [true, null] })).toBe(describeCanonical({ a: [true, null], b: 1 }));
        expect(describeCanonical({ a: 1 })).not.toBe(describeCanonical({ a: 2 }));
    });
});

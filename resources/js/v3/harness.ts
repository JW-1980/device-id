/**
 * Measurement helpers for the browser harness (tests/Browser/transport-checks.mjs) ONLY.
 *
 * Nothing in the application imports this module, and `index.ts` must never re-export it:
 * the production collector chunk is a dynamic entry whose export names survive
 * minification, so anything exported from `index.ts` ships to every visitor under a
 * readable name (notes/24 finding F6). These two had no production consumer, so they live
 * here, and the harness bundles this module separately from source. The harness also
 * asserts that the BUILT collector chunk does not export them.
 *
 * `measureProbes` and `measurePhases` stay in `index.ts`: the admin demo page
 * (Pages/Admin/Security/FingerprintDemo.vue) calls them in production.
 */

import { canonicalise, type ProbeResult } from './canonical';
import { TIER, VALUE_PROBES } from './value-probes';

/**
 * Run Tier 1 alone and report per-probe timings. A budget assertion is only useful if a
 * failure can be attributed to a probe.
 */
export async function measureTierOne(): Promise<Array<{ name: string; state: string; ms: number }>> {
    const entries = await Promise.all(
        VALUE_PROBES.filter((entry) => entry.tier === TIER.ONE).map(async (entry) => {
            const started = performance.now();
            const result = await entry.run();
            return {
                name: entry.name,
                state: (result as ProbeResult<unknown>).state,
                ms: Math.round((performance.now() - started) * 1000) / 1000,
            };
        }),
    );

    return entries;
}

/**
 * The canonical serialisation the digest is computed over, for the harness's determinism
 * check (two fresh contexts must produce byte-identical stable claims). Deliberately does
 * NOT expose the digest.
 */
export const describeCanonical = canonicalise;

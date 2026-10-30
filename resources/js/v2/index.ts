/**
 * The fingerprint collector: challenge, collect, hash, send.
 *
 * ## The shape of it
 *
 * ```
 *   1. POST /security/fingerprint/challenge  ->  { token, purpose, expires_at }
 *   2. collect()             ->  integrity + tier 1        SYNCHRONOUS, cheap
 *   3. POST /security/fingerprint/claims   via fetch(keepalive), so it survives unload
 *   4. collectTier2()        ->  the expensive probes      IN IDLE TIME
 *   5. POST /security/fingerprint/claims   a second envelope, same token family
 * ```
 *
 * ## Why tier 2 is a SEPARATE call, which a measurement forced
 *
 * The design said tier 2 should be deferred to idle time. The first implementation
 * ran it inline at the end of `collect()`, behind a budget guard, and the real-browser
 * check rejected it on every engine:
 *
 * | engine | cold | warm | slowest single probe |
 * |---|---|---|---|
 * | Chromium | 49.2 ms | 37.2 ms | `fontFallback` 22.9 ms |
 * | Firefox  | 42.0 ms | 154 ms  | `audioRealtime` 9.0 ms |
 * | WebKit   | 152 ms  | 31.0 ms | `errorText` 9.0 ms |
 *
 * None of those is fixable by being cleverer about the guard. The costs are genuine
 * first-use initialisation â€” a canvas backend, an audio device path, the font
 * fallback machinery â€” and they are paid once per page. Tier 2 is 25-30 ms of work
 * that is *by design* not urgent, so putting it in the critical path was simply the
 * wrong architecture, and the budget guard was papering over it.
 *
 * So `collect()` is now integrity + tier 1 only: measured at 1.5 ms in Chromium and
 * under 20 ms everywhere including WebKit, with the integrity probes â€” the only ones
 * that can detect an attacker at all â€” inside that number.
 *
 * ## Ordering inside the synchronous part
 *
 * **integrity first.** Measured at 30/30 cells against a stealth spoofer, while 0 of
 * 162 value-probe runs detected anything. Putting them first means that if the user
 * navigates away, the tab is backgrounded, or the budget runs out, the half that is
 * worth having has already been collected.
 *
 * ## What is never done
 *
 * - No `eval`, no `new Function`, no `setTimeout` with a string body. The CSP is
 *   nonce-based and `enforce` is one env flag away. Asserted against the built bundle
 *   in tests/Browser/transport-checks.mjs.
 * - No DOM mutation, no `console.*`. A collector that touches the DOM is observable
 *   by the page, breaks sites that diff their own markup, and appears in their error
 *   reporting.
 * - No throw. Every failure path ends in a sent envelope with fewer fields, or in no
 *   envelope at all. A fingerprint collector that can take down the page it is
 *   protecting has failed at its only job.
 */

import { xsrfToken } from '../shared/xsrf';
import { claimDigest, canonicalise, type ProbeResult } from './canonical';
import { behavior, hasBehaviorData, startBehaviorCollection } from './behavior';
import { collectIntegrity } from './integrity';
import {
    FINGERPRINT_VERSION,
    type Challenge,
    type CollectedClaims,
    type CollectionPurpose,
    type DeclineReason,
} from './protocol';
import { sendClaims, sendClaimsAndConfirm, sendDecline } from './transport';
import { TIER, VALUE_PROBES, runTier } from './value-probes';

export type { Challenge, CollectedClaims, CollectionPurpose, DeclineReason } from './protocol';
export { FINGERPRINT_VERSION } from './protocol';

/**
 * Budget for the SYNCHRONOUS part only.
 *
 * Tier 2 has its own, much larger, separately-deferred budget, because it is not on
 * the critical path. A single combined number was the mistake: it made the guard
 * look like a safety net for a cost that should never have been paid there at all.
 */
export const BUDGET_MS = 30;

/** Tier-2 budget, applied in idle time rather than on load. Generous on purpose. */
export const TIER2_BUDGET_MS = 250;

export interface CollectionResult {
    readonly claims: CollectedClaims;
    readonly digest: string;
    /** True when the integrity probes found nothing. */
    readonly ok: boolean;
}

const round3 = (value: number): number => Math.round(value * 1000) / 1000;

const now = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());

/**
 * Resolve a tier's mixed sync/async results.
 *
 * `runTier` returns some probes' values and some probes' promises, because most of
 * the measured cost is synchronous rasterisation that the event loop cannot overlap
 * anyway, while the async ones (UA-CH, permissions, audio) genuinely can. Awaiting
 * them concurrently keeps the wall-clock close to the slowest probe rather than the
 * sum, and turns a failed probe into `null` in the payload instead of rejecting the
 * whole collection.
 */
async function resolveAll(
    raw: Readonly<Record<string, ProbeResult<unknown> | Promise<ProbeResult<unknown>>>>,
): Promise<Record<string, unknown>> {
    const entries = await Promise.all(
        Object.entries(raw).map(async ([name, result]) => {
            const settled = await result;

            return [name, settled.state === 'ok' ? settled.value : { state: settled.state }] as const;
        }),
    );

    return Object.fromEntries(entries);
}

/**
 * Strip every measurement from a claim set, leaving only facts.
 *
 * The digest is computed over THIS, not over the claim set as sent. The claim set
 * carries a timing block and per-probe elapsed times because they are useful
 * diagnostics, and the real-browser check caught the consequence of hashing them
 * directly: the digest changed on every single page load, so every visit looked like
 * a new device and the identifier was worth nothing.
 *
 * Three separate attempts at this, all caught by a test, and the pattern is worth
 * stating because it will recur:
 *
 * 1. Raw timing in the claim set â€” `collect()` determinism test failed.
 * 2. Bucketed timing in the claim set â€” real-browser check failed, bucket flipping
 *    across a reload at the boundary.
 * 3. Timing in the claim set but excluded from the diff â€” digest instability,
 *    because the digest was computed over the unstripped set.
 *
 * The rule that survives all three: **the identifier is a function of facts only.
 * Measurements are reported alongside it, never inside it.**
 */
function stableClaims(claims: CollectedClaims): Record<string, unknown> {
    return JSON.parse(
        JSON.stringify(claims, (key, value) => (key === 'timing' || key === 'elapsedMs' ? undefined : value)),
    ) as Record<string, unknown>;
}

/**
 * The SYNCHRONOUS collection: integrity probes plus tier 1.
 *
 * Tier 2 is deliberately not here. See the module docblock for the measurement that
 * forced the split â€” `collect()` used to run it inline behind a budget guard and cost
 * 42-152 ms cold across the three engines, which the real-browser check rejected on
 * every one of them.
 *
 * Never throws. Pure with respect to the network, so it is testable without a server.
 *
 * Per-phase timings are measured during development and deliberately not sent. The split
 * exists so the cost of each phase is knowable; the phase marks themselves were left in
 * here from that work, and were removed because nothing consumed them and their presence
 * implied a field in the envelope that does not exist. A client also chooses what to
 * report about its own cost, so a per-phase figure could not be scored â€” `elapsedMs` is
 * in the envelope for the budget and for the operator's benefit, and nothing more.
 */
export async function collect(challenge: Challenge, purpose: CollectionPurpose): Promise<CollectionResult> {
    const started = now();

    // Integrity first: measured at 30/30 cells against a stealth spoofer, and the
    // only probes in the subsystem that can detect an attacker by themselves.
    const integrity = collectIntegrity();

    const tier1 = await resolveAll(await runTier(TIER.ONE));
    const finished = now();

    const claims: CollectedClaims = {
        v: FINGERPRINT_VERSION,
        purpose,
        integrity: {
            findings: integrity.findings,
            data: integrity.data as unknown as Record<string, unknown>,
            elapsedMs: integrity.elapsedMs,
        },
        tier1,
        timing: {
            elapsedMs: round3(finished - started),
            budgetMs: BUDGET_MS,
            // Always false here: nothing is deferred within this call. Kept in the
            // shape so the server can tell "tier 1 only" from "tier 1 and tier 2"
            // without a second envelope type.
            tier2Skipped: false,
        },
    };

    return {
        claims,
        digest: await claimDigest(stableClaims(claims)),
        ok: integrity.findings.length === 0,
    };
}

/**
 * The DEFERRED collection: tier 2, in idle time.
 *
 * Call from `requestIdleCallback` (or a `setTimeout` fallback where that is absent).
 * Sends a second envelope. The server merges it with the first by digest, so a user
 * who leaves before idle time still has a usable claim set â€” a smaller one, and the
 * server can see that it is smaller because `tier2Skipped` is in the first envelope.
 *
 * The alternative â€” one combined call â€” was measured and rejected; see the module
 * docblock.
 */
export async function collectTier2(challenge: Challenge, purpose: CollectionPurpose): Promise<CollectionResult> {
    const started = now();

    const tier2 = await resolveAll(await runTier(TIER.TWO));
    const finished = now();

    const claims: CollectedClaims = {
        v: FINGERPRINT_VERSION,
        purpose,
        integrity: { findings: [], data: {}, elapsedMs: 0 },
        tier1: {},
        tier2,
        timing: {
            elapsedMs: round3(finished - started),
            budgetMs: TIER2_BUDGET_MS,
            tier2Skipped: false,
        },
    };

    return { claims, digest: await claimDigest(stableClaims(claims)), ok: true };
}

/**
 * Build a behaviour-only tier-2 envelope from the passive aggregates.
 *
 * Returns null when there has been no input, so a page with no interaction does not send
 * a default that would hash as if it were a device value. This is a separate envelope from
 * `collectTier2` because it is sent on unload, after the visitor has had time to type,
 * move the pointer or touch the screen; the tier-2 idle snapshot usually runs too early.
 */
export async function collectBehavior(
    challenge: Challenge,
    purpose: CollectionPurpose,
): Promise<CollectionResult | null> {
    const started = now();
    const snapshot = behavior();

    if (snapshot.state !== 'ok') {
        return null;
    }

    const claims: CollectedClaims = {
        v: FINGERPRINT_VERSION,
        purpose,
        integrity: { findings: [], data: {}, elapsedMs: 0 },
        tier1: {},
        tier2: { behavior: snapshot.value },
        timing: {
            elapsedMs: round3(now() - started),
            budgetMs: TIER2_BUDGET_MS,
            tier2Skipped: false,
        },
    };

    return { claims, digest: await claimDigest(stableClaims(claims)), ok: true };
}

/**
 * Send the behaviour snapshot once, when the page is hidden or unloaded.
 *
 * The server merges tier2 probe maps by key, so this envelope does not replace the idle
 * tier-2 envelope; it adds `behavior` to it. The token's uses are bounded, and this is the
 * third and final one. No listener is left behind after the send.
 */
export function scheduleBehaviorReport(
    challenge: Challenge,
    purpose: CollectionPurpose,
    claimsUrl?: string,
): void {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        return;
    }

    startBehaviorCollection();

    let sent = false;

    const cleanup = (): void => {
        try {
            window.removeEventListener('pagehide', send);
            document.removeEventListener('visibilitychange', onVisibility);
        } catch {
            // A target that cannot remove has nothing registered.
        }
    };

    const send = (): void => {
        if (sent) {
            return;
        }
        sent = true;
        cleanup();

        if (!hasBehaviorData()) {
            return;
        }

        void collectBehavior(challenge, purpose).then((result) => {
            if (result !== null && claimsUrl) {
                sendClaims(claimsUrl, { challenge, digest: result.digest, claims: result.claims });
            }
        });
    };

    const onVisibility = (): void => {
        if (document.visibilityState === 'hidden') {
            send();
        }
    };

    try {
        window.addEventListener('pagehide', send, { once: true });
        document.addEventListener('visibilitychange', onVisibility);
    } catch {
        // A target that rejects the listener simply gets the idle tier-2 snapshot only.
    }
}

/**
 * Schedule the deferred tier-2 collection.
 *
 * Returns the promise so a caller can await it in a test. A no-op when idle time
 * never arrives, which is normal: a tab that is backgrounded or closing will not get
 * one, and that is the correct outcome rather than a reason to run it eagerly.
 */
export function scheduleTier2(
    challenge: Challenge,
    purpose: CollectionPurpose,
    onDone?: (result: CollectionResult) => void,
    claimsUrl?: string,
): Promise<CollectionResult | null> {
    const run = (): void => {
        void collectTier2(challenge, purpose).then((result) => {
            if (claimsUrl) {
                sendClaims(claimsUrl, { challenge, digest: result.digest, claims: result.claims });
            }
            onDone?.(result);
        });
    };

    if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(run, { timeout: 3000 });
    } else if (typeof setTimeout === 'function') {
        setTimeout(run, 400);
    }

    // Resolves to null when idle time never arrives, which the caller can ignore.
    return new Promise((resolve) => {
        if (typeof requestIdleCallback === 'function') {
            requestIdleCallback(() => resolve(null), { timeout: 3000 });
        } else {
            setTimeout(() => resolve(null), 400);
        }
    });
}

/**
 * The full round trip: fetch a challenge, collect, send.
 *
 * Every failure resolves rather than rejects. A collector that can reject is a
 * collector that can break a sign-in form, and there is no fingerprint value worth
 * that. Silent on purpose, and deliberately without a `console` call: nothing here is
 * actionable by the visitor, and a collector that logs is visible to the page it is
 * inspecting.
 */
export async function collectAndSend(
    purpose: CollectionPurpose,
    challengeUrl = '/security/fingerprint/challenge',
    claimsUrl = '/security/fingerprint/claims',
): Promise<CollectionResult | null> {
    if (typeof document === 'undefined' || typeof fetch !== 'function') {
        return null;
    }

    try {
        startBehaviorCollection();

        const challenge = await fetchChallenge(purpose, challengeUrl);
        if (challenge === null) {
            return null;
        }

        const result = await collect(challenge, purpose);
        sendClaims(claimsUrl, { challenge, digest: result.digest, claims: result.claims });

        // Tier 2 is scheduled, not awaited. Awaiting it here is the mistake the
        // real-browser check caught: it put 25-150 ms of canvas, font and audio
        // initialisation on the critical path of a sign-in form.
        scheduleTier2(challenge, purpose, undefined, claimsUrl);
        scheduleBehaviorReport(challenge, purpose, claimsUrl);

        return result;
    } catch {
        return null;
    }
}

/**
 * Ask the server for a single-use challenge for this purpose. `null` on any failure.
 */
async function fetchChallenge(purpose: CollectionPurpose, challengeUrl: string): Promise<Challenge | null> {
    // A POST, not a GET, and with the CSRF header.
    //
    // Both changed when the endpoints were built. The challenge route rides the `web`
    // group, and `bootstrap/app.php` pins the CSRF exemption to `api/*` only â€” rule
    // V5-02, enforced by tests/Feature/Architecture/CsrfExemptionTest â€” so these paths
    // cannot be exempted and a request without the token is a 419. The old `GET
    // /_fp/challenge` was written when no route existed at all, which is the only
    // reason it was a GET: there was nothing to be a POST *to*.
    const response = await fetch(challengeUrl, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'X-XSRF-TOKEN': xsrfToken(),
            accept: 'application/json',
        },
        // The purpose is sent here and validated server-side against the deployment's
        // own list, which is deliberately short and excludes the catalogue. A caller
        // cannot widen it.
        body: JSON.stringify({ purpose }),
        credentials: 'same-origin',
        // A cached challenge is a spent challenge.
        cache: 'no-store',
    });

    if (!response.ok) {
        return null;
    }

    // No `salt` to check for any more. The rotating salt existed so a `sendBeacon`,
    // which cannot set headers, could prove its own integrity; with the client MAC
    // gone the beacon is gone too, and CSRF plus the single-use token do the job the
    // salt was standing in for. See transport.ts.
    const challenge = (await response.json()) as Challenge;
    if (typeof challenge?.token !== 'string' || challenge.token === '') {
        return null;
    }

    return challenge;
}

/**
 * Collect tier 1 and wait until the server has recorded it, for a decision that needs the
 * device known first (a guest vote). Tier 2 still follows at idle time.
 *
 * Resolves `true` once the claims were accepted; `false` on any failure, never rejects.
 */
export async function collectAndConfirm(
    purpose: CollectionPurpose,
    challengeUrl = '/security/fingerprint/challenge',
    claimsUrl = '/security/fingerprint/claims',
): Promise<boolean> {
    if (typeof document === 'undefined' || typeof fetch !== 'function') {
        return false;
    }

    try {
        const challenge = await fetchChallenge(purpose, challengeUrl);
        if (challenge === null) {
            return false;
        }

        const result = await collect(challenge, purpose);
        const accepted = await sendClaimsAndConfirm(claimsUrl, {
            challenge,
            digest: result.digest,
            claims: result.claims,
        });
        scheduleTier2(challenge, purpose, undefined, claimsUrl);

        return accepted;
    } catch {
        return false;
    }
}

/**
 * Tell the server the collector was asked and declined.
 *
 * ## Why this is a separate exported function and not a fallback inside `collectAndSend`
 *
 * A browser that refuses to run the collector never gets a challenge, because the
 * challenge request is itself the thing that needs a working environment. So the decline
 * is issued by whoever *knows* the browser refused â€” a caller catching a `SecurityError`
 * from a probe, or a wrapper that decided not to run at all â€” not by the collector itself.
 *
 * The alternative, having the collector post a decline when its own probes fail, was
 * rejected: a probe failing is not the same as a browser refusing, and conflating them
 * would mean a single canvas error on a locked-down machine is recorded as a refusal.
 *
 * ## Why it is worth a request at all
 *
 * Because a declined client is scored on its Phase 1 transport evidence rather than on
 * nothing, and the server cannot do that unless it is told the request was made. Without
 * this, the most useful fact about a privacy-protective browser â€” that its transport is
 * entirely normal â€” is never recorded, and the row that would prove the control is safe to
 * ship does not exist.
 */
export async function reportDeclined(
    claimsUrl: string,
    reason: DeclineReason,
    challengeUrl = '/security/fingerprint/challenge',
): Promise<boolean> {
    if (typeof fetch !== 'function') {
        return false;
    }

    // A decline still has to consume a token, or one token would buy unlimited declines and
    // the observation table would fill with rows no challenge ever backed. The token is
    // therefore fetched first, and the decline is only posted if that succeeded.
    return fetch(challengeUrl, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'X-XSRF-TOKEN': xsrfToken(),
            accept: 'application/json',
        },
        body: JSON.stringify({ purpose: 'signin' }),
        credentials: 'same-origin',
        cache: 'no-store',
    })
        .then((response) => (response.ok ? response.json() : null))
        .then((challenge: Challenge | null) =>
            challenge && typeof challenge.token === 'string'
                ? sendDecline(claimsUrl, challenge, reason)
                : false,
        )
        .catch(() => false);
}

/**
 * Run Tier 1 alone and report per-probe timings.
 *
 * Exists for `tests/Browser/transport-checks.mjs`, and it exists because the budget
 * assertion is only useful if a failure can be *attributed*. "Collection took 283 ms"
 * is a number to act on; "283 ms" with no per-probe breakdown is an argument to
 * have. A budget check that cannot say which probe broke it gets disabled.
 *
 * Also the honest way to measure the synchronous tier: the first version of the
 * harness called an internal name that did not exist and measured 0.0 ms through an
 * optional chain â€” a passing number that meant nothing.
 */
export async function measureTierOne(): Promise<Array<{ name: string; state: string; ms: number }>> {
    const entries = await Promise.all(
        VALUE_PROBES.filter((entry) => entry.tier === TIER.ONE).map(async (entry) => {
            const started = now();
            const result = await entry.run();
            return {
                name: entry.name,
                state: (result as ProbeResult<unknown>).state,
                ms: Math.round((now() - started) * 1000) / 1000,
            };
        }),
    );

    return entries;
}

/**
 * Per-probe timings for the whole set, integrity included.
 *
 * Diagnostic only, and never hashed â€” nothing measured belongs in the identifier.
 * See the `domBlockers` docblock for the two attempts at including a measurement and
 * why both were reverted.
 *
 * **Runs sequentially on purpose.** The first version used `Promise.all`, and every
 * probe reported roughly the same time â€” around 80 ms for a probe the research
 * measured at 0.02 ms. With concurrent execution each probe's clock starts before any
 * of the others finish, so every row measures the whole batch and the breakdown says
 * nothing. A diagnostic that cannot localise an overrun is worse than no diagnostic,
 * because it looks like data.
 */
export async function measureProbes(): Promise<Array<{ name: string; tier: number; state: string; ms: number }>> {
    const rows: Array<{ name: string; tier: number; state: string; ms: number }> = [];

    const integrityStart = now();
    collectIntegrity();
    rows.push({
        name: 'integrity',
        tier: 0,
        state: 'ok',
        ms: Math.round((now() - integrityStart) * 1000) / 1000,
    });

    for (const entry of VALUE_PROBES) {
        const started = now();
        const result = await entry.run();
        rows.push({
            name: entry.name,
            tier: entry.tier,
            state: (result as ProbeResult<unknown>).state,
            ms: Math.round((now() - started) * 1000) / 1000,
        });
    }

    return rows;
}

/**
 * Phase-level timings, for localising a budget overrun.
 *
 * `measureProbes()` says WHICH probe is slow. This says which PHASE is slow, which
 * is the question you have to answer first â€” because a per-probe breakdown that adds
 * up to 25 ms while the collection takes 216 ms is telling you the cost is not in
 * the probes, and that is a much more useful thing to know than a list of 17 small
 * numbers.
 *
 * Diagnostic only; see `measureProbes` for why nothing measured is ever hashed.
 */
export async function measurePhases(): Promise<Record<string, number>> {
    const phases: Record<string, number> = {};

    let start = now();
    collectIntegrity();
    phases.integrity = round3(now() - start);

    start = now();
    await runTier(TIER.ONE);
    phases.tierOne = round3(now() - start);

    start = now();
    await runTier(TIER.TWO);
    phases.tierTwo = round3(now() - start);

    start = now();
    await claimDigest({ probe: 'x' });
    phases.firstDigest = round3(now() - start);

    start = now();
    await claimDigest({ probe: 'y' });
    phases.secondDigest = round3(now() - start);

    start = now();
    await collect({ token: 't', purpose: 'signin', expiresAt: 0 }, 'signin');
    phases.fullCollect = round3(now() - start);

    return phases;
}

/**
 * Exposed for the admin "why was this flagged" panel and for tests.
 *
 * Deliberately does NOT expose the digest: a canonicaliser that can also produce the
 * digest is a canonicaliser whose output is one `await` away from being logged.
 */
export const describeCanonical = canonicalise;

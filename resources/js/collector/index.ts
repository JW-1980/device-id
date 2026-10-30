/**
 * The fingerprint collector: challenge, collect, hash, send.
 *
 * ```
 *   1. POST /security/fingerprint/challenge  ->  { token, purpose, expires_at }
 *   2. collect()        ->  integrity + tier 1                 synchronous
 *   3. POST /security/fingerprint/claims   slot 'tier1'      fetch(keepalive)
 *   4. collectTier2()   ->  tier 2 + hardware probes          idle slices, one probe each
 *   5. POST /security/fingerprint/claims   slot 'tier2', SAME nonce, AFTER the tier-1 response
 * ```
 *
 * The token is redeemable once per slot. The server attaches the `tier2` envelope to the
 * observation the `tier1` envelope created, looked up by the nonce; the client digest
 * plays no part in that and is never trusted. The tier-2 POST waits for the tier-1 response
 * (round-2 R2-08): a tier-2 envelope that overtook its tier-1 envelope found no observation
 * to attach to and spent its slot of the token for nothing.
 *
 * ## Why tier 2 is a separate envelope
 *
 * Tier 2 is first-use initialisation of canvas, audio and font machinery (50-250 ms in a
 * cold renderer, measured on three engines). Running it inline put that on the critical
 * path of a sign-in form, so it runs after the first envelope is away, in idle time — one
 * probe per slice, each started only while the idle deadline has room (value-probes.ts
 * `runDeferred`) — and a visitor who leaves early still produced a usable tier-1 envelope.
 *
 * ## Cost of the synchronous part
 *
 * `collect()` measured 13-15 ms cold in Chromium 153 on 2026-10-05 (first-use canvas work
 * inside the integrity phase; `buildFingerprint`'s ICU load is tier 2 now) and 3-6 ms warm;
 * tests/Browser/transport-checks.mjs prints the per-engine numbers on every run.
 *
 * ## The host decides endpoints and purposes
 *
 * `collectAndSend(purpose, challengeUrl, claimsUrl)` takes all three from the caller: the
 * purpose is any string the host's challenge endpoint accepts, and the URLs default to
 * `/security/fingerprint/challenge` and `/security/fingerprint/claims`. Pages without a
 * single-page application start it through `boot.ts` (`data-fingerprint-*` attributes).
 *
 * ## Behaviour is session data
 *
 * `behavior` (behavior.ts) aggregates pointer, keyboard, wheel, touch and motion input from
 * the moment `collectAndSendDetailed` starts until the tier-2 snapshot is taken, then the
 * listeners are removed. It rides in the tier-2 envelope; a later snapshot (on page hide) would
 * need a third envelope slot, which the challenge store does not have. The server keeps it out
 * of every key.
 *
 * ## The method policy
 *
 * An operator can switch individual non-core probes off (`ProbeRegistry` on the server). The
 * list arrives as `disabled_probes` in the challenge response (`collect`, `collectTier2`) or
 * as `<meta name="nc-fingerprint-disabled">` on the page (`collectForIdentity`, which has no
 * challenge). A disabled probe is not run and is ABSENT from the claims — not `unavailable`:
 * the server applies the same policy and does not expect it. Core probes (`CORE_PROBES`) and
 * names that match no probe are ignored. The policy is not echoed back; the server has it.
 *
 * ## What is never done
 *
 * - No `eval`, no `new Function`, no `setTimeout` with a string body. The CSP is
 *   nonce-based and `enforce` is one env flag away. Asserted against the built bundle
 *   in tests/Browser/transport-checks.mjs.
 * - No persistent DOM mutation and no `console.*` call from this code. The one transient
 *   mutation: `phantomRealm` (phantom.ts) attaches one hidden, `aria-hidden` iframe to
 *   `document.documentElement` and removes it again (in a `finally`) within the deferred
 *   integrity slice; the elements it measures live inside that iframe and go with it. Canvases
 *   are created detached and never inserted. (The engine itself may log when WebGL is
 *   unavailable; the harness prints those lines.)
 * - No throw from the public functions. Every failure path ends in a sent envelope with
 *   fewer fields, a decline, or nothing.
 */

import { xsrfToken } from '../shared/xsrf';
import { startBehaviorCollection, stopBehaviorCollection } from './behavior';
import { claimDigest, type ProbeResult } from './canonical';
import { collectDeferredIntegrity, collectIntegrity, type IntegrityReport } from './integrity';
import {
    effectiveDisabled,
    FINGERPRINT_VERSION,
    type Challenge,
    type CollectedClaims,
    type CollectionPurpose,
    type DeclineReason,
    type EnvelopeSlot,
} from './protocol';
import { acquireShared, releaseShared } from './shared';
import { sendClaims, sendDecline, type SendResult } from './transport';
import { TIER, VALUE_PROBES, nextIdle, runDeferred, runTier, type UnitTrace } from './value-probes';

export type { SendFailure, SendResult } from './transport';
export type { Challenge, CollectedClaims, CollectionPurpose, DeclineReason, EnvelopeSlot } from './protocol';
export { FINGERPRINT_VERSION } from './protocol';
// The identify path (resources/js/utils/deviceIdentity.ts) applies the same body ceiling
// as the challenge path, from this one chunk, so the two cannot drift.
export { claimHeaders, payloadBytes, TRANSPORT_LIMITS } from './transport';
export type { UnitTrace } from './value-probes';

/** Budget for the SYNCHRONOUS part only, reported in the envelope for the operator. */
export const BUDGET_MS = 30;

/** Tier-2 budget, applied in idle time rather than on load. Generous on purpose. */
export const TIER2_BUDGET_MS = 250;

export interface CollectionResult {
    readonly claims: CollectedClaims;
    /** Which envelope slot this result is sent as. */
    readonly slot: EnvelopeSlot;
    /** Unkeyed canonical hash; '' where the page has no SubtleCrypto. Debugging only. */
    readonly digest: string;
    /** True when the integrity probes found nothing. */
    readonly ok: boolean;
}

const round3 = (value: number): number => Math.round(value * 1000) / 1000;

const now = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());

/** A probe's wire form: the raw value when ok, `{ state }` otherwise. */
const unwrapForWire = (settled: ProbeResult<unknown>): unknown =>
    settled.state === 'ok' ? settled.value : { state: settled.state };

/**
 * Resolve a tier's mixed sync/async results. A failed probe becomes `{ state }` in the
 * payload instead of rejecting the whole collection.
 */
async function resolveAll(
    raw: Readonly<Record<string, ProbeResult<unknown> | Promise<ProbeResult<unknown>>>>,
): Promise<Record<string, unknown>> {
    const entries = await Promise.all(
        Object.entries(raw).map(async ([name, result]) => [name, unwrapForWire(await result)] as const),
    );

    return Object.fromEntries(entries);
}

/**
 * Strip every measurement from a claim set, leaving only facts.
 *
 * The digest is computed over THIS. Hashing the timing block made every page load a new
 * device, three different ways, each caught by a test: the identifier is a function of
 * facts only, and measurements are reported alongside it, never inside it.
 */
function stableClaims(claims: CollectedClaims): Record<string, unknown> {
    return JSON.parse(
        JSON.stringify(claims, (key, value) => (key === 'timing' || key === 'elapsedMs' ? undefined : value)),
    ) as Record<string, unknown>;
}

/** The digest, or '' where SubtleCrypto is absent (http origins). Never throws. */
async function digestOf(claims: CollectedClaims): Promise<string> {
    try {
        return await claimDigest(stableClaims(claims));
    } catch {
        // The digest is a debugging aid, never an identifier (see `stableClaims`): the
        // server ignores it, so a missing one costs nothing, and '' is the documented
        // "no digest" value that the harness and `buildEnvelope` already carry.
        return '';
    }
}

/** The meta tag the identify path reads its method policy from. */
export const DISABLED_META_NAME = 'nc-fingerprint-disabled';

/**
 * The method policy from `<meta name="nc-fingerprint-disabled" content="a,b,c">`, for the
 * identify path. Absent, empty, or no `document` → `[]` (run everything). Never throws.
 */
export function readDisabledMeta(): string[] {
    try {
        if (typeof document === 'undefined') return [];
        const content = document.querySelector(`meta[name="${DISABLED_META_NAME}"]`)?.getAttribute('content');
        return typeof content === 'string' ? effectiveDisabled(content.split(',')) : [];
    } catch {
        // A malformed selector or a hostile document means "no policy", which is the
        // documented safe default: run everything. The server's own policy still applies.
        return [];
    }
}

/**
 * The SYNCHRONOUS collection: integrity probes plus tier 1, minus the probes the
 * challenge's policy disables. Never throws.
 */
export async function collect(challenge: Challenge, purpose: CollectionPurpose): Promise<CollectionResult> {
    const disabled = effectiveDisabled(challenge.disabledProbes);
    const started = now();

    // Integrity first: if the visitor navigates away, the half that can detect tampering
    // has already been collected.
    const integrity = collectIntegrity(disabled);

    const tier1 = await resolveAll(await runTier(TIER.ONE, disabled));
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
            // Always false here: nothing is deferred within this call. Kept in the shape
            // so the server can tell "tier 1 only" from "tier 1 and tier 2".
            tier2Skipped: false,
        },
    };

    return {
        claims,
        slot: 'tier1',
        digest: await digestOf(claims),
        ok: integrity.findings.length === 0,
    };
}

/**
 * The DEFERRED collection: tier 2 and the hardware probes, run in idle slices and
 * merged into one `tier2` block. The shared WebGL and audio contexts are released at the
 * end. Never throws.
 */
export async function collectTier2(challenge: Challenge, purpose: CollectionPurpose): Promise<CollectionResult> {
    const started = now();

    const deferred = startDeferred(effectiveDisabled(challenge.disabledProbes));
    await deferred.finished;
    const { tier2, integrity } = deferred.snapshot();
    const finished = now();

    const claims: CollectedClaims = {
        v: FINGERPRINT_VERSION,
        purpose,
        // The DEFERRED integrity phase (phantomRealm, plus resistance and canvasFill
        // re-measured as data for this envelope's own trust decisions). Present: the run
        // was awaited to the end, and that phase is its first slice.
        integrity: {
            findings: integrity?.findings ?? [],
            data: (integrity?.data ?? {}) as unknown as Record<string, unknown>,
            elapsedMs: integrity?.elapsedMs ?? 0,
        },
        tier1: {},
        tier2,
        timing: {
            elapsedMs: round3(finished - started),
            budgetMs: TIER2_BUDGET_MS,
            tier2Skipped: false,
        },
    };

    return { claims, slot: 'tier2', digest: await digestOf(claims), ok: (integrity?.findings.length ?? 0) === 0 };
}

/** A deferred collection in flight: what has settled so far, and a way to stop scheduling more. */
interface DeferredRun {
    /** Settles when the schedule ends (completed or stopped after the running unit). Never rejects. */
    readonly finished: Promise<void>;
    /** Stop starting new units; the one running (if any) completes and is included. */
    readonly abort: () => void;
    /** The probes settled so far, in wire form, and the deferred integrity phase if it ran. */
    readonly snapshot: () => { tier2: Record<string, unknown>; integrity: IntegrityReport | undefined };
}

/**
 * Start the deferred collection: the deferred integrity phase in the first idle slice, then
 * tier 2 and the hardware probes through the scheduler (value-probes.ts `runDeferred`: one
 * probe per slice, deadline-aware, audio probes last). The shared WebGL and audio contexts
 * are released when the schedule ends, whatever happened — unless another collection still
 * holds them.
 *
 * `collectDeferredIntegrity` runs in the FIRST idle slice, on its own, before any tier-2
 * probe: `phantomRealm` costs 8-36 ms warm (a fresh iframe realm), which broke the 30 ms
 * synchronous budget, and a slice that also held a tier-2 probe would be a long task.
 *
 * Results are readable WHILE the run is in flight (`snapshot`), so a caller with a cap of
 * its own (`collectForIdentity`) can stop the schedule and send what has settled instead of
 * nothing (decision G-D5i).
 */
function startDeferred(disabled: readonly string[], trace?: (unit: UnitTrace) => void): DeferredRun {
    let stopped = false;
    let integrity: IntegrityReport | undefined;
    const results: Record<string, ProbeResult<unknown>> = {};

    const finished = (async (): Promise<void> => {
        // A hold, not an unconditional release: another collection may be using the same
        // shared contexts and worker right now (shared.ts `acquireShared`).
        const release = acquireShared();
        try {
            const budget = await nextIdle();
            if (stopped) return;
            const startMs = now();
            try {
                integrity = collectDeferredIntegrity(disabled);
            } finally {
                trace?.({ name: 'integrityDeferred', step: null, slice: 0, startMs, endMs: now(), remainingMs: budget.timeRemaining() });
            }

            await runDeferred([TIER.TWO, TIER.HARDWARE], { disabled, aborted: () => stopped, trace, out: results, firstSlice: 1 });
        } catch {
            // Nothing above throws by contract; a surprise ends the schedule with what it has.
        } finally {
            release();
        }
    })();

    return {
        finished,
        abort: (): void => {
            stopped = true;
        },
        snapshot: () => ({
            tier2: Object.fromEntries(Object.entries(results).map(([name, result]) => [name, unwrapForWire(result)])),
            integrity,
        }),
    };
}

/**
 * The synchronous and deferred integrity phases as ONE report, for the identify path's
 * single claim set: findings concatenated, `data` merged with the deferred keys winning (the
 * only overlap is `canvasFill`/`resistance`, which the deferred phase re-measures), and the
 * two durations summed.
 */
function mergeIntegrity(sync: IntegrityReport, deferred: IntegrityReport | undefined): IntegrityReport {
    if (!deferred) return sync;

    return {
        findings: [...sync.findings, ...deferred.findings],
        data: { ...sync.data, ...deferred.data },
        elapsedMs: round3(sync.elapsedMs + deferred.elapsedMs),
    };
}

/** The claim set the identify path posts: `CollectedClaims` without a `purpose`. */
export type IdentityClaims = Omit<CollectedClaims, 'purpose'>;

/** How long the identify path waits for the chunked tier 2 before sending tier 1 alone. */
export const IDENTITY_TIER2_TIMEOUT_MS = 5000;

/**
 * Both tiers in ONE claim set, for `POST /device/identify`
 * (resources/js/utils/deviceIdentity.ts): no challenge, no envelope, nothing sent, and
 * no `purpose` — that endpoint has one purpose by construction. Tier 1 is collected
 * synchronously; tier 2 (with the hardware probes) is given at most `tier2TimeoutMs`. When
 * the cap passes, the schedule is stopped and the claim set carries WHAT HAS SETTLED by then
 * (decision G-D5i: a visitor whose idle time ran out still yields the probes that did run,
 * and the server's coverage says which did not); `timing.tier2Skipped` is true only when
 * nothing of tier 2 settled, and `tier2` is then absent. A unit that was running when the
 * cap passed completes in the background and releases its contexts itself. Never throws for
 * a probe's failure (a probe's failure is `{ state }`).
 *
 * `disabled` defaults to the page's `<meta name="nc-fingerprint-disabled">` policy, and is
 * sanitised like the challenge's (core and non-string names dropped).
 */
export async function collectForIdentity(
    tier2TimeoutMs = IDENTITY_TIER2_TIMEOUT_MS,
    disabled: readonly string[] = readDisabledMeta(),
): Promise<IdentityClaims> {
    const policy = effectiveDisabled(disabled);
    const started = now();

    const integrity = collectIntegrity(policy);
    const tier1 = await resolveAll(await runTier(TIER.ONE, policy));

    const deferred = startDeferred(policy);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        await Promise.race([
            deferred.finished,
            new Promise<void>((resolve) => {
                timer = setTimeout(() => {
                    deferred.abort();
                    resolve();
                }, tier2TimeoutMs);
            }),
        ]);
    } finally {
        if (timer !== undefined) {
            clearTimeout(timer);
        }
    }
    const finished = now();
    const settled = deferred.snapshot();
    const tier2 = Object.keys(settled.tier2).length > 0 ? settled.tier2 : undefined;
    const merged = mergeIntegrity(integrity, settled.integrity);

    return {
        v: FINGERPRINT_VERSION,
        integrity: {
            findings: merged.findings,
            data: merged.data as unknown as Record<string, unknown>,
            elapsedMs: merged.elapsedMs,
        },
        tier1,
        ...(tier2 === undefined ? {} : { tier2 }),
        timing: {
            elapsedMs: round3(finished - started),
            budgetMs: BUDGET_MS + TIER2_BUDGET_MS,
            tier2Skipped: tier2 === undefined,
        },
    };
}

/**
 * Schedule the deferred tier-2 collection and, when `claimsUrl` is given, send it as
 * the `tier2` envelope under the same nonce — only once `tier1Delivered` has resolved
 * TRUE (the tier-1 envelope was answered 2xx). A tier-1 envelope that was refused, dropped
 * or never answered has no observation for the tier-2 envelope to attach to, and sending
 * one anyway spent the token's tier-2 slot on a refusal (round-2 R2-08 / BE2-10). The
 * collection itself does not wait: it runs in idle time while the tier-1 request is in
 * flight, and only the POST is held back.
 *
 * Resolves with the result once it has been collected (and the send started or skipped),
 * or with `null` if the collection failed. `requestIdleCallback` with a timeout runs even
 * when the page never goes idle; Safari has no `requestIdleCallback` and uses a short timer.
 */
export function scheduleTier2(
    challenge: Challenge,
    purpose: CollectionPurpose,
    onDone?: (result: CollectionResult) => void,
    claimsUrl?: string,
    tier1Delivered: Promise<boolean> = Promise.resolve(true),
): Promise<CollectionResult | null> {
    return scheduleTier2Send(challenge, purpose, onDone, claimsUrl, tier1Delivered).then((outcome) => outcome.result);
}

/** What the deferred tier-2 pass did: the collected result (null if collection failed) and the send. */
export interface Tier2Outcome {
    readonly result: CollectionResult | null;
    /**
     * null when no `claimsUrl` was given (collect only), collection failed, or the tier-1
     * envelope was not answered 2xx (`tier1Delivered: false`), so nothing was sent.
     */
    readonly send: SendResult | null;
    /** Whether the tier-1 envelope was answered 2xx; null when there was no send to wait for. */
    readonly tier1Delivered: boolean | null;
    /** The collection failure, when `result` is null. */
    readonly error?: unknown;
}

/** `scheduleTier2` with the send outcome surfaced (round-4 frontend review); never rejects. */
export function scheduleTier2Send(
    challenge: Challenge,
    purpose: CollectionPurpose,
    onDone?: (result: CollectionResult) => void,
    claimsUrl?: string,
    tier1Delivered: Promise<boolean> = Promise.resolve(true),
): Promise<Tier2Outcome> {
    return new Promise((resolve) => {
        const run = (): void => {
            collectTier2(challenge, purpose)
                .then(async (result) => {
                    // The behaviour snapshot is part of `result`; the listeners have done their job.
                    stopBehaviorCollection();
                    let send: SendResult | null = null;
                    let tier1WasDelivered: boolean | null = null;
                    if (claimsUrl) {
                        tier1WasDelivered = await tier1Delivered.catch(() => false);
                        if (tier1WasDelivered) {
                            send = sendClaims(claimsUrl, { challenge, slot: 'tier2', digest: result.digest, claims: result.claims });
                        }
                    }
                    try {
                        onDone?.(result);
                    } catch {
                        /* a listener's failure is not the collector's */
                    }
                    resolve({ result, send, tier1Delivered: tier1WasDelivered });
                })
                // `collectTier2` never throws by contract; a rejection here is a bug, and it
                // is returned as `error` so the caller can show it. It is not logged: this
                // module makes no `console.*` call.
                .catch((error: unknown) => {
                    stopBehaviorCollection();
                    resolve({ result: null, send: null, tier1Delivered: null, error });
                });
        };

        if (typeof requestIdleCallback === 'function') {
            requestIdleCallback(run, { timeout: 3000 });
        } else {
            setTimeout(run, 400);
        }
    });
}

const CHALLENGE_HEADERS = (): Record<string, string> => ({
    'content-type': 'application/json',
    'X-XSRF-TOKEN': xsrfToken(),
    accept: 'application/json',
});

/** Why no challenge was obtained. */
export type ChallengeFailure = 'http' | 'malformed' | 'network';

export type ChallengeOutcome =
    | { readonly challenge: Challenge }
    | { readonly challenge: null; readonly reason: ChallengeFailure; readonly status?: number; readonly error?: unknown };

/**
 * Obtain a challenge, with the failure cause. A POST with the CSRF header: the route rides
 * the `web` group and cannot be CSRF-exempted (rule V5-02). Never throws.
 */
export async function requestChallenge(challengeUrl: string, purpose: CollectionPurpose): Promise<ChallengeOutcome> {
    try {
        const response = await fetch(challengeUrl, {
            method: 'POST',
            headers: CHALLENGE_HEADERS(),
            // Validated server-side against the deployment's own purpose list.
            body: JSON.stringify({ purpose }),
            credentials: 'same-origin',
            // A cached challenge is a spent challenge.
            cache: 'no-store',
        });
        if (!response.ok) {
            return { challenge: null, reason: 'http', status: response.status };
        }

        const challenge = (await response.json()) as Challenge & { disabled_probes?: unknown; expires_at?: unknown };
        if (typeof challenge?.token !== 'string' || challenge.token === '') {
            return { challenge: null, reason: 'malformed' };
        }

        // The wire is snake_case (`expires_at`, `disabled_probes`); an already camelCased
        // response is still accepted. The policy is sanitised here: a malformed one means
        // "run everything", never a failed collection.
        const expiresAt = typeof challenge.expires_at === 'number' ? challenge.expires_at : challenge.expiresAt;
        const disabledProbes = effectiveDisabled(challenge.disabled_probes ?? challenge.disabledProbes);

        return { challenge: { ...challenge, expiresAt, disabledProbes } };
    } catch (error) {
        // A network failure or a body that is not JSON; the cause is returned.
        return { challenge: null, reason: 'network', error };
    }
}

/**
 * Obtain a challenge. Returns null on any failure; `requestChallenge` says which. Exported so
 * the response mapping (`expires_at`, `disabled_probes`) can be tested directly.
 */
export async function fetchChallenge(challengeUrl: string, purpose: CollectionPurpose): Promise<Challenge | null> {
    return (await requestChallenge(challengeUrl, purpose)).challenge;
}

/**
 * What a full round trip did. `status` discriminates:
 *
 * - `sent`: collected and the tier-1 request was started (`send.delivered` settles with the
 *   server's answer). `tier2` settles with the deferred pass.
 * - `send-failed`: collected, but the tier-1 request was NOT started (`send` has the reason).
 * - `unsupported`: no `document` or no `fetch`; nothing was attempted.
 * - `no-challenge`: no challenge was issued (`challenge` has the cause); nothing was sent.
 * - `collect-failed`: the collection threw; the token was spent on a decline (`declined`).
 */
export type CollectAndSendOutcome =
    | { readonly status: 'sent'; readonly result: CollectionResult; readonly send: SendResult; readonly tier2: Promise<Tier2Outcome> }
    | { readonly status: 'send-failed'; readonly result: CollectionResult; readonly send: SendResult }
    | { readonly status: 'unsupported' }
    | { readonly status: 'no-challenge'; readonly challenge: Extract<ChallengeOutcome, { challenge: null }> }
    | { readonly status: 'collect-failed'; readonly reason: DeclineReason; readonly error: unknown; readonly declined: SendResult };

/**
 * The full round trip: fetch a challenge, collect, send tier 1, schedule tier 2, and say what
 * happened. Never rejects.
 *
 * Nothing is logged: a collector that can break a sign-in form has failed at its only job.
 * When `collect()` itself fails after a challenge was issued, the token is spent on a
 * decline instead, so the server still records that this client was asked.
 */
export async function collectAndSendDetailed(
    purpose: CollectionPurpose,
    challengeUrl = '/security/fingerprint/challenge',
    claimsUrl = '/security/fingerprint/claims',
): Promise<CollectAndSendOutcome> {
    if (typeof document === 'undefined' || typeof fetch !== 'function') {
        return { status: 'unsupported' };
    }

    // Before the challenge round trip, so the first input is not lost to it. Every path that
    // does not reach the tier-2 pass stops it again (a listener must not outlive its use).
    startBehaviorCollection();

    const issued = await requestChallenge(challengeUrl, purpose);
    if (issued.challenge === null) {
        stopBehaviorCollection();

        return { status: 'no-challenge', challenge: issued };
    }
    const challenge = issued.challenge;
    if (effectiveDisabled(challenge.disabledProbes).includes('behavior')) {
        // The operator switched the method off: it is not collected, and the server does not expect it.
        stopBehaviorCollection();
    }

    let result: CollectionResult;
    try {
        result = await collect(challenge, purpose);
    } catch (error) {
        stopBehaviorCollection();
        // `name` is read structurally: a DOMException from another realm is not an
        // `instanceof Error` here, and its name is the fact that matters.
        const name = typeof error === 'object' && error !== null ? (error as { name?: unknown }).name : undefined;
        const reason: DeclineReason = name === 'SecurityError' ? 'blocked' : 'unavailable';

        return { status: 'collect-failed', reason, error, declined: sendDecline(claimsUrl, challenge, reason) };
    }

    const send = sendClaims(claimsUrl, { challenge, slot: 'tier1', digest: result.digest, claims: result.claims });
    if (!send.sent) {
        // Tier 2 is not scheduled either: the server would hold a tier-2 envelope for a
        // token whose tier-1 slot was never filled.
        stopBehaviorCollection();

        return { status: 'send-failed', result, send };
    }

    // Scheduled, not awaited: awaiting it put 25-150 ms of canvas, font and audio
    // initialisation on the critical path of a sign-in form. The tier-1 request is in flight;
    // its `delivered` promise is handed to the tier-2 schedule, which posts its envelope only
    // after this one was answered 2xx (round-2 R2-08).
    return { status: 'sent', result, send, tier2: scheduleTier2Send(challenge, purpose, undefined, claimsUrl, send.delivered) };
}

/**
 * Compatibility wrapper over `collectAndSendDetailed`: the collection result when the tier-1
 * request was started, `null` when nothing was sent (any other status). Callers that need
 * the cause use `collectAndSendDetailed`.
 */
export async function collectAndSend(
    purpose: CollectionPurpose,
    challengeUrl = '/security/fingerprint/challenge',
    claimsUrl = '/security/fingerprint/claims',
): Promise<CollectionResult | null> {
    const outcome = await collectAndSendDetailed(purpose, challengeUrl, claimsUrl);

    return outcome.status === 'sent' ? outcome.result : null;
}

/**
 * Collect tier 1 and wait until the server has answered it 2xx, for a decision that needs the
 * device recorded first (a guest vote: the response sets the device cookie the vote then
 * carries). Tier 2 still follows in idle time. Resolves `true` once the claims were accepted;
 * `false` on any failure (nothing sent, refused, or the network failed), and never rejects.
 * The caller bounds the wait itself (`Promise.race` with its own timeout).
 */
export async function collectAndConfirm(
    purpose: CollectionPurpose,
    challengeUrl = '/security/fingerprint/challenge',
    claimsUrl = '/security/fingerprint/claims',
): Promise<boolean> {
    const outcome = await collectAndSendDetailed(purpose, challengeUrl, claimsUrl);

    return outcome.status === 'sent' ? outcome.send.delivered : false;
}

/**
 * Tell the server the collector was asked and declined.
 *
 * A decline must consume a token, or one token would buy unlimited declines. With a
 * `challenge` in hand (the `collectAndSend` failure path) that token is used; otherwise
 * one is fetched for the given purpose first. Resolves with whether the server answered
 * the decline 2xx (false when no token could be had, or the request failed or was refused).
 */
export async function reportDeclined(
    claimsUrl: string,
    reason: DeclineReason,
    challengeUrl = '/security/fingerprint/challenge',
    purpose: CollectionPurpose = 'signin',
    challenge?: Challenge,
): Promise<boolean> {
    if (typeof fetch !== 'function') {
        return false;
    }

    const token = challenge ?? (await fetchChallenge(challengeUrl, purpose));

    return token ? sendDecline(claimsUrl, token, reason).delivered : false;
}

/**
 * Per-probe timings for the whole set, integrity included. Diagnostic only, never hashed.
 *
 * Runs SEQUENTIALLY on purpose: under `Promise.all` every row measures the whole batch
 * and the breakdown says nothing.
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

    const deferredStart = now();
    collectDeferredIntegrity();
    rows.push({
        name: 'integrityDeferred',
        tier: 0,
        state: 'ok',
        ms: Math.round((now() - deferredStart) * 1000) / 1000,
    });

    try {
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
    } finally {
        releaseShared();
    }

    return rows;
}

/**
 * The deferred collection exactly as `collectTier2` / `collectForIdentity` schedule it, with
 * a per-unit trace: which idle slice each probe (or `fontMetrics` step) ran in, when it
 * started and settled, and how much of the idle period was left when it started. The
 * harness aligns the Long Tasks API's entries with these windows to attribute a long task
 * to a slice; the admin demo may show the table. Diagnostic only; nothing here is hashed or
 * sent. The probes' values are discarded.
 */
export async function measureDeferred(disabled: readonly string[] = []): Promise<UnitTrace[]> {
    const units: UnitTrace[] = [];
    const run = startDeferred(effectiveDisabled(disabled), (unit) => units.push(unit));
    await run.finished;

    return units;
}

/**
 * Phase-level timings, for localising an overrun to a phase before a probe. Diagnostic
 * only; nothing measured is ever hashed.
 */
export async function measurePhases(): Promise<Record<string, number>> {
    const phases: Record<string, number> = {};

    let start = now();
    collectIntegrity();
    phases.integrity = round3(now() - start);

    start = now();
    collectDeferredIntegrity();
    phases.integrityDeferred = round3(now() - start);

    start = now();
    await runTier(TIER.ONE);
    phases.tierOne = round3(now() - start);

    try {
        start = now();
        await runTier(TIER.TWO);
        phases.tierTwo = round3(now() - start);

        start = now();
        await runTier(TIER.HARDWARE);
        phases.hardware = round3(now() - start);
    } finally {
        releaseShared();
    }

    start = now();
    await claimDigest({ probe: 'x' }).catch(() => '');
    phases.firstDigest = round3(now() - start);

    start = now();
    await claimDigest({ probe: 'y' }).catch(() => '');
    phases.secondDigest = round3(now() - start);

    start = now();
    await collect({ token: 't', purpose: 'signin', expiresAt: 0 }, 'signin');
    phases.fullCollect = round3(now() - start);

    return phases;
}

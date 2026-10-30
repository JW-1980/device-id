/**
 * The wire contract between the browser collector and the server.
 *
 * ## Why this is its own module
 *
 * `index.ts` (the orchestrator) and `transport.ts` (the delivery) both need these
 * names, and importing them from each other creates a cycle - a value import of
 * `FINGERPRINT_VERSION` from the orchestrator into the transport, which the
 * orchestrator imports. Bundlers untangle that, but it is a design smell: it means
 * the delivery layer depends on the thing that is trying to deliver, and the
 * protocol is nowhere you would look for it.
 *
 * So the protocol lives here, imports nothing from the rest of the subsystem, and
 * both sides depend on it instead of on each other.
 *
 * ## Versioning
 *
 * `FINGERPRINT_VERSION` is the envelope version, not the bundle version. It changes
 * when the SHAPE changes, so the server can reject a payload it cannot read rather
 * than misinterpreting one. A field being added is a minor change and increments it;
 * the server treats an unknown version as "no claims", never as "claims missing".
 *
 * v3 adds `slot`: one challenge token is redeemable once per slot, so the tier-1
 * envelope and the deferred tier-2 envelope of one visit share a nonce and the server
 * attaches the second to the observation created by the first.
 */

/** Bumped when the claim set or envelope shape changes. */
export const FINGERPRINT_VERSION = 3;

/**
 * Which set of probes this bundle runs, sent as `probes` in every envelope.
 *
 * Bumped whenever a probe is ADDED (the server's `ProbeRegistry::PROBE_SET`, kept equal by
 * `tests/Unit/ProbeSetTest`; set 3 added `webrtc` and `behavior`). The server's omission gate expects of an envelope
 * only the probes of the set it reports, so a page left open across a deploy, still running
 * the previous bundle, is judged against the probes that bundle actually has. A body without
 * the marker is judged against set 1, the bundle that predates it.
 *
 * Not a version of the envelope SHAPE (`FINGERPRINT_VERSION`): an added probe is an added
 * key, which every server version already reads.
 */
export const PROBE_SET = 3;

/** Which half of one visit an envelope carries. The token is redeemable once per slot. */
export type EnvelopeSlot = 'tier1' | 'tier2';

/**
 * Why a collection is running.
 *
 * The server applies a policy per purpose. This is not telemetry about the visitor:
 * it is the collection point telling the server which decision the claims are
 * relevant to, so the server can apply the threshold for that decision rather than a
 * global one. The surfaces are deliberately few and chosen so a collection only ever
 * runs where a real decision is being made - see DESIGN.md task 3.1 for why the
 * catalogue pages are excluded.
 *
 * The collector does not know the list: each host configures its own purposes server-side
 * (the challenge endpoint refuses any other), and the host passes the one it wants as a plain
 * string (`collectAndSend('signin')`, `data-fingerprint-purpose="vote"`). A name the server
 * does not know only produces a refused challenge, never a wrong collection.
 */
export type CollectionPurpose = string;

/**
 * What the server issues, and what the envelope must echo back.
 *
 * ## There is no `salt` field, and that is a deliberate change
 *
 * The first version of this interface had a rotating server-held `salt`, and the client
 * used it to compute a MAC over the canonical claims so a `sendBeacon` — which cannot
 * set headers — could still prove the envelope was not tampered with in transit.
 *
 * That is gone, for two reasons that only became clear once the endpoints existed:
 *
 * 1. **The server no longer verifies a client MAC.** `ClientClaimsEnvelope` has no `sig`
 *    field and its docblock says why: freshness comes from the single-use token and
 *    session binding comes from the device-cookie compare, both server-side and both
 *    stronger than a client-held key. A MAC proved the *client* did not alter its own
 *    claims, which was never the property that mattered — the client controls its own
 *    JavaScript, so it can simply not send one.
 *
 * 2. **The reason for `sendBeacon` is therefore gone too.** CSRF covers cross-origin
 *    submission, and `bootstrap/app.php` pins the CSRF exemption to `api/*` only
 *    (`tests/Feature/Architecture/CsrfExemptionTest`, V5-02), so these routes cannot be
 *    exempted. A beacon cannot carry the token, so the beacon cannot be used. `fetch`
 *    with `keepalive` can, and outlives the document just as well.
 *
 * So the interface is smaller, the transport is a `fetch`, and the salt is nowhere. The
 * `Challenge` was the last place a secret lived on the client.
 */
export interface Challenge {
    /**
     * Single-use. A replayed token makes every downstream check advisory, and it is the
     * only thing tying an envelope to this request.
     */
    readonly token: string;
    /** Echoed back so the client can confirm it was not issued for a different surface. */
    readonly purpose: CollectionPurpose;
    readonly expiresAt: number;
    /**
     * The operator's method policy: probe names the collector must skip, from the challenge
     * response's `disabled_probes` (mapped by `fetchChallenge`). Absent means "run all".
     * Never trusted as-is: `effectiveDisabled()` drops anything that is not a string and every
     * core name before it is used.
     */
    readonly disabledProbes?: readonly string[];
}

/**
 * The probes that can never be switched off, whatever a policy says (CONTRACT-2 §N).
 *
 * They feed `browser_key` / `hardware_key`, or they are the two integrity probes the design
 * calls the most important in the system, or (`resistance`) they decide which components
 * the server may trust at all. The server never sends them in a policy
 * (`ProbeRegistry`); the client drops them anyway, so a tampered or mistaken policy cannot
 * re-key every device or switch tamper detection off.
 */
export const CORE_PROBES: readonly string[] = [
    'environment', 'uaClientHints', 'dateParsing', 'codecs', 'esFeatures', 'objectShape',
    'removedApiBoundary', 'cssMedia', 'architecture', 'audioRealtime', 'audioHardware',
    'wrongReceiver', 'descriptorIntegrity',
    // Core since the five-review round: it gates the server's per-component trust projection
    // (a component measured under Brave/RFP/Tor is not trusted), so switching it off would
    // silently make noised components count as identity.
    'resistance',
    // Core since round 4: the engine marks are the evidence that lets the server honour a
    // resistFingerprinting/Tor report at all. Switched off, every honest RFP/Tor visitor was
    // linked to its whole cohort by the shared browser key again.
    'engineIdentity',
];

/**
 * A policy list as the collector applies it: strings only, trimmed, de-duplicated, core
 * names removed. Anything that is not an array is "no policy". Unknown names survive and
 * are harmless — they match no probe — so a server that knows a newer probe than this
 * bundle does not break it.
 */
export function effectiveDisabled(names: unknown): string[] {
    if (!Array.isArray(names)) {
        return [];
    }

    const out = new Set<string>();
    for (const name of names) {
        if (typeof name !== 'string') continue;
        const trimmed = name.trim();
        if (trimmed !== '' && !CORE_PROBES.includes(trimmed)) out.add(trimmed);
    }

    return [...out];
}

/** Why the collector produced no claims. A closed set the server recognises. */
export type DeclineReason = 'blocked' | 'unavailable' | 'unsupported' | 'precondition_failed';

/**
 * One tamper finding: a code from integrity.ts `INTEGRITY_CODES`, and nothing else.
 * Evidence about the environment, never a device value.
 *
 * There is no `detail` field. Clients before 2026-10-05 also sent an English sentence per
 * finding; the server never read it (it lifts findings by `code`, counts entries, and writes
 * its own sentence), so it was dropped from the wire. The server still accepts a finding
 * that carries one, because a cached old bundle keeps sending it.
 */
export interface IntegrityFinding {
    readonly code: string;
}

export interface TimingReport {
    readonly elapsedMs: number;
    readonly budgetMs: number;
    /** True when tier 2 was skipped for budget. Its absence is itself a signal. */
    readonly tier2Skipped: boolean;
}

export interface CollectedClaims {
    readonly v: number;
    readonly purpose: CollectionPurpose;
    readonly integrity: {
        /** Only NON-CLEAN findings. Empty is the normal result for a real browser. */
        readonly findings: readonly IntegrityFinding[];
        readonly data: Readonly<Record<string, unknown>>;
        readonly elapsedMs: number;
    };
    readonly tier1: Readonly<Record<string, unknown>>;
    /** Absent when the budget ran out. */
    readonly tier2?: Readonly<Record<string, unknown>>;
    readonly timing: TimingReport;
}

export interface Envelope {
    readonly v: number;
    /**
     * The token from the challenge, which the server redeems once per slot.
     *
     * Sent as `nonce` rather than `token` to match the field the server's envelope parser
     * reads first; the parser accepts either name, because a rolling deploy has to accept
     * a client bundle that is still in somebody's browser cache.
     */
    readonly nonce: string;
    /** `tier1` for the synchronous half, `tier2` for the deferred half of the same visit. */
    readonly slot: EnvelopeSlot;
    /**
     * The bundle's probe set (`PROBE_SET`). Optional on the type only so a body built by an
     * older bundle still type-checks in tests; every current envelope carries it.
     */
    readonly probes?: number;
    /**
     * Unkeyed SHA-256 of the canonical claims, for debugging only and never trusted.
     * Empty when the page has no SubtleCrypto (an insecure context).
     */
    readonly digest: string;
    /** The claims themselves, so a decision can be explained after the fact. */
    readonly claims: CollectedClaims;
}

/**
 * The body posted when the collector was asked and declined.
 *
 * A different shape from `Envelope`, not a flag on it. `ClientDecline::parse()` refuses a
 * body carrying both, because "which one was meant" is the question a prober wants
 * answered by watching which one gets honoured — and because an envelope with an empty
 * `claims` object would put a fabricated empty measurement into every downstream
 * calculation, which is exactly what an empty claim set is meant to avoid meaning.
 */
export interface DeclineEnvelope {
    readonly v: number;
    readonly nonce: string;
    readonly declined: true;
    readonly reason: DeclineReason;
}

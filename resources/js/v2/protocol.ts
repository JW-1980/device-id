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
 */

/** Bumped when the claim set or envelope shape changes. */
export const FINGERPRINT_VERSION = 2;

/**
 * Why a collection is running.
 *
 * The server applies a policy per purpose. This is not telemetry about the visitor:
 * it is the collection point telling the server which decision the claims are
 * relevant to, so the server can apply the threshold for that decision rather than a
 * global one. The surfaces are deliberately few and chosen so a collection only ever
 * runs where a real decision is being made - see DESIGN.md task 3.1 for why the
 * catalogue pages are excluded.
 */
export type CollectionPurpose =
    | 'signin'
    | 'register'
    | 'password_reset'
    | 'checkout'
    | 'account_security'
    | 'vote';

export const COLLECTION_PURPOSES: readonly CollectionPurpose[] = [
    'signin',
    'register',
    'password_reset',
    'checkout',
    'account_security',
    'vote',
];

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
}

/** Why the collector produced no claims. A closed set the server recognises. */
export type DeclineReason = 'blocked' | 'unavailable' | 'unsupported' | 'precondition_failed';

/** One tamper finding. Evidence about the environment, never a device value. */
export interface IntegrityFinding {
    readonly code: string;
    readonly detail: string;
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
     * The single-use token from the challenge, which the server redeems exactly once.
     *
     * Sent as `nonce` rather than `token` to match the field the server's envelope parser
     * reads first; the parser accepts either name, because a rolling deploy has to accept
     * a client bundle that is still in somebody's browser cache.
     */
    readonly nonce: string;
    /** Keyed hash of the canonical claims, recorded for debugging and never trusted. */
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

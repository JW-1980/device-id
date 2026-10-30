/**
 * Transport for the claim set and for a decline.
 *
 * ## Why `fetch(keepalive)` and not `sendBeacon`
 *
 * This used to be `sendBeacon`, and the reason was stated in this file as "it cannot set
 * headers, so the envelope has to carry its own integrity". Both halves of that are now
 * wrong:
 *
 * 1. **The envelope no longer carries its own integrity.** There is no client MAC. The
 *    first `Challenge` had a rotating server-held `salt` and the client keyed a hash over
 *    the canonical claims with it. The server never verified one, and does not now â€”
 *    `ClientClaimsEnvelope` has no `sig` field, and the docblock says why. Freshness
 *    comes from the single-use token and session binding from the device-cookie compare,
 *    both server-side, both stronger than anything a client holding its own key can prove.
 *    A MAC proved the client did not alter its own claims, which was never the property
 *    that mattered: the client controls its own JavaScript, so it can simply not send one.
 *
 * 2. **The header is now required.** CSRF is the control that stops a third-party site
 *    submitting claims on a visitor's behalf, and `bootstrap/app.php` pins the CSRF
 *    exemption to `api/*` only â€” `tests/Feature/Architecture/CsrfExemptionTest`, rule
 *    V5-02. These routes are not under `api/`, so they cannot be exempted, so a request
 *    without the token is a 419. A beacon cannot send it.
 *
 * `keepalive` is the fetch equivalent and is designed for exactly the case the beacon was
 * chosen for: the browser lets the request outlive the document. The honest cost is that
 * a `keepalive` request is subject to a much smaller size budget than a beacon's shared
 * buffer, which is why the size guard below is against a small constant rather than the
 * old 24 KB.
 *
 * ## Why no compression
 *
 * A raw claim set is roughly 8-15 KB, which is inside the keepalive budget. The honest
 * response to "it might be too large" is a size guard and a documented fallback â€” not a
 * compression path nothing exercises. Compression here would be untested code on a
 * request every sign-in makes, which is a liability rather than an optimisation. If the
 * measured payload ever crosses the limit, the right change is to drop probes.
 */

import { xsrfToken } from '../shared/xsrf';
import {
    FINGERPRINT_VERSION,
    type Challenge,
    type CollectedClaims,
    type DeclineEnvelope,
    type DeclineReason,
    type Envelope,
} from './protocol';

/**
 * The keepalive body budget, conservatively.
 *
 * Browsers cap a `keepalive` body at 64 KB in total across in-flight requests, and some
 * implementations count headers against it. Claim sets measured at 8-15 KB, so 32 KB is
 * generous and still leaves room for a second concurrent request. The old constant was
 * 24 KB against the beacon's shared buffer, which is a different limit and no longer the
 * relevant one â€” the number changed because the transport did, not because the payload did.
 */
const MAX_PAYLOAD_BYTES = 32 * 1024;

export interface ClaimsPayload {
    readonly challenge: Challenge;
    readonly digest: string;
    readonly claims: CollectedClaims;
}

/**
 * Build the envelope.
 *
 * The claims travel verbatim as well as the digest, and both are needed. The digest is
 * recorded for debugging and cross-referencing; the claims are what the server's
 * constraint table reads. A server that stored only a hash could not explain a decision to
 * an operator, and a server that stored only claims would have to re-derive the hash.
 */
export function buildEnvelope(payload: ClaimsPayload): Envelope {
    return {
        v: FINGERPRINT_VERSION,
        nonce: payload.challenge.token,
        digest: payload.digest,
        claims: payload.claims,
    };
}

/**
 * Build the decline body.
 *
 * A different shape, not a flag on the envelope â€” see `DeclineEnvelope`. It carries the
 * token so the server can redeem it: without that, one token would buy unlimited declines
 * and the observation table would fill with rows no challenge ever backed.
 */
export function buildDecline(challenge: Challenge, reason: DeclineReason): DeclineEnvelope {
    return {
        v: FINGERPRINT_VERSION,
        nonce: challenge.token,
        declined: true,
        reason,
    };
}

/**
 * Deliver the envelope.
 *
 * Returns whether the request was *started*, which is NOT whether it arrived. That
 * distinction is documented because it is the kind of thing that gets "fixed" by a caller
 * retrying on false â€” and a retry of a single-use token is exactly the wrong thing to do,
 * so this function's boolean exists to report "could not even try", not "try again".
 */
export function sendClaims(url: string, payload: ClaimsPayload): boolean {
    return post(url, buildEnvelope(payload));
}

/**
 * Tell the server the collector was asked and declined.
 *
 * Worth a request: a declined client is scored on its Phase 1 transport evidence rather
 * than on nothing, and the server cannot do that unless it is told the request was made.
 * Without this the highest-value thing about a privacy-protective browser â€” that its
 * transport is perfectly normal â€” is never recorded.
 *
 * Best-effort by design. It uses `keepalive` like the claim path, but a failure here costs
 * one missing row and must never surface to the page.
 */
export function sendDecline(url: string, challenge: Challenge, reason: DeclineReason): boolean {
    return post(url, buildDecline(challenge, reason));
}

/**
 * The one request path, so the CSRF header, the content type and the size guard cannot
 * drift between the claim and decline calls.
 */
function post(url: string, body: Envelope | DeclineEnvelope): boolean {
    const init = requestInit(body);
    if (init === null) {
        return false;
    }

    try {
        void fetch(url, init).catch(() => false);

        return true;
    } catch {
        return false;
    }
}

/**
 * Send the claims and wait for the server to accept them.
 *
 * For the one place a decision needs the device recorded before it is made: a guest vote.
 * The response sets the encrypted device cookie, so the vote that follows carries it.
 * Resolves `false` on any failure rather than rejecting, like the rest of the collector.
 */
export async function sendClaimsAndConfirm(url: string, payload: ClaimsPayload): Promise<boolean> {
    const init = requestInit(buildEnvelope(payload));
    if (init === null) {
        return false;
    }

    try {
        const response = await fetch(url, init);

        return response.ok;
    } catch {
        return false;
    }
}

/**
 * The one request shape, so the CSRF header, the content type and the size guard cannot
 * drift between the claim and decline calls. `null` when there is nothing to send.
 */
function requestInit(body: Envelope | DeclineEnvelope): RequestInit | null {
    if (typeof fetch !== 'function') {
        return null;
    }

    const json = JSON.stringify(body);

    // An oversized keepalive body is rejected by the browser with an unhelpful error, and
    // the claim set is not worth an exception on a sign-in form. This is a drop, not a
    // truncation: a partial claim set would be scored as if it were the whole thing.
    if (json.length > MAX_PAYLOAD_BYTES) {
        return null;
    }

    return {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            // The encrypted cookie value, which is the only form ValidateCsrfToken
            // decrypts before comparing. `X-CSRF-TOKEN` carries the same string and
            // is compared verbatim, so it is refused - see xsrf.ts.
            'X-XSRF-TOKEN': xsrfToken(),
            accept: 'application/json',
        },
        body: json,
        credentials: 'same-origin',
        keepalive: true,
    };
}

export const TRANSPORT_LIMITS = { maxPayloadBytes: MAX_PAYLOAD_BYTES } as const;

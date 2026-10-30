/**
 * Transport for the claim set and for a decline.
 *
 * ## Why `fetch(keepalive)` and not `sendBeacon`
 *
 * CSRF is the control that stops a third-party site submitting claims on a visitor's
 * behalf, and `bootstrap/app.php` pins the CSRF exemption to `api/*` only
 * (`tests/Feature/Architecture/CsrfExemptionTest`, rule V5-02). These routes are not
 * under `api/`, so a request without the `X-XSRF-TOKEN` header is a 419, and a beacon
 * cannot send a header. `keepalive` lets the request outlive the document just as a
 * beacon would. There is no client MAC: freshness comes from the single-use-per-slot
 * token and session binding from the device-cookie compare, both server-side.
 *
 * ## Size guard
 *
 * The server rejects any body over `security.fingerprint.max_body_bytes` (24 KiB, 24 576
 * bytes, counted in bytes; see `MAX_PAYLOAD_BYTES` below) with the same constant response it
 * gives a stored envelope, so the client must not send one. Measured on 2026-10-08 (harness,
 * Chromium 153 on a bare Linux container): the identify body about 15 KB (14 919-14 985 B),
 * the tier-2 challenge envelope 7.40 KiB; a real device carries more font, voice and renderer
 * evidence. Per the Fetch specification the keepalive quota is 64 KiB of body per fetch group,
 * shared with `sendBeacon`, so this guard is inside it. No compression: if the payload ever
 * crosses the limit, the right change is to drop probes.
 *
 * ## What the send functions report
 *
 * `SendResult` says whether the request was started and, when it was not, why (no `fetch`,
 * a body over the limit, a synchronous throw such as a claim `JSON.stringify` cannot
 * serialise). This module never calls `console.*` (the collector's no-console rule), so the
 * reason travels in the return value to whoever can show it (round-4 frontend review: a
 * failed send used to be indistinguishable from "nothing to send"). Whether a started
 * request was ANSWERED 2xx is `delivered`; why it was not (network, 4xx/5xx) is not
 * reported: `keepalive` requests are fired as the page may be unloading, the token is
 * single-use per slot so a retry would be refused, and there is nobody to tell.
 */

import { xsrfToken } from '../shared/xsrf';
import {
    FINGERPRINT_VERSION,
    PROBE_SET,
    type Challenge,
    type CollectedClaims,
    type DeclineEnvelope,
    type DeclineReason,
    type Envelope,
    type EnvelopeSlot,
} from './protocol';

/**
 * The SERVER limit (`config/security.php` fingerprint.max_body_bytes and
 * `IdentifyDeviceRequest::MAX_BODY_BYTES`), in bytes. 24 KiB since notes/22: the identify-path
 * body measured 15.1 KB in a bare Chromium container, and a real device carries longer
 * renderer, voice and font evidence; a body over this ceiling is never sent, which would be
 * a silent loss of identification, so the ceiling keeps about 1.6x headroom over that.
 *
 * A CONSTANT that mirrors the DEFAULT of `security.fingerprint.max_body_bytes` (24576, env
 * `SECURITY_FINGERPRINT_MAX_BODY`); the page is not told the effective server value (round-3
 * CL3-9). So the env value must not be set BELOW 24576 without changing this constant in the
 * same release: the client would keep sending bodies the server answers with 413, and every
 * such visitor would back off and retry hourly without ever being identified (the loop
 * round-2 PERF-21 removed). Raising the server value is harmless but has no effect here.
 */
const MAX_PAYLOAD_BYTES = 24 * 1024;

export interface ClaimsPayload {
    readonly challenge: Challenge;
    readonly slot: EnvelopeSlot;
    readonly digest: string;
    readonly claims: CollectedClaims;
}

/** Why a send was not started. */
export type SendFailure = 'no-fetch' | 'oversize' | 'threw';

/**
 * The outcome of one send. `sent: true` means the request was STARTED; `delivered` resolves
 * with whether the server ANSWERED 2xx (false when it was never started) and never rejects.
 * `bytes` is the UTF-8 body size when it was computed (always for `oversize`).
 */
export type SendResult =
    | { readonly sent: true; readonly bytes: number; readonly delivered: Promise<boolean> }
    | { readonly sent: false; readonly reason: SendFailure; readonly bytes?: number; readonly error?: unknown; readonly delivered: Promise<boolean> };

/** Build the envelope. The claims travel verbatim; the digest is a debugging aid only. */
export function buildEnvelope(payload: ClaimsPayload): Envelope {
    return {
        v: FINGERPRINT_VERSION,
        nonce: payload.challenge.token,
        slot: payload.slot,
        probes: PROBE_SET,
        digest: payload.digest,
        claims: payload.claims,
    };
}

/**
 * Build the decline body.
 *
 * A different shape, not a flag on the envelope — see `DeclineEnvelope`. It carries the
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
 * Reports whether the request was STARTED and, when it was not, why; `delivered` resolves
 * with whether the server ANSWERED 2xx (false when it was not started, failed on the network,
 * or was refused). A retry on a failure would replay a token the server will not honour twice
 * per slot, so the result is information, never "try again". `delivered` is what the tier-2
 * schedule waits for before posting its own envelope (index.ts `scheduleTier2`, round-2
 * R2-08); the request itself starts synchronously inside this call. Never throws.
 */
export function sendClaims(url: string, payload: ClaimsPayload): SendResult {
    return post(url, buildEnvelope(payload));
}

/**
 * Tell the server the collector was asked and declined, so the declined client is scored
 * on its transport evidence rather than on nothing. Best-effort; never surfaces to the page.
 * Same contract as `sendClaims`.
 */
export function sendDecline(url: string, challenge: Challenge, reason: DeclineReason): SendResult {
    return post(url, buildDecline(challenge, reason));
}

/** UTF-8 byte length, which is what the server's limit counts. */
export function payloadBytes(json: string): number {
    return typeof TextEncoder === 'function' ? new TextEncoder().encode(json).byteLength : json.length;
}

/**
 * The one request path, so the CSRF header, the content type and the size guard cannot
 * drift between the claim and decline calls. The `fetch` is issued synchronously (before
 * the first `await`), so a caller that does not wait still has the request in flight.
 */
function post(url: string, body: Envelope | DeclineEnvelope): SendResult {
    if (typeof fetch !== 'function') {
        return { sent: false, reason: 'no-fetch', delivered: Promise.resolve(false) };
    }

    try {
        const json = JSON.stringify(body);
        const bytes = payloadBytes(json);

        // A drop, not a truncation: a partial claim set would be scored as if it were whole.
        if (bytes > MAX_PAYLOAD_BYTES) {
            return { sent: false, reason: 'oversize', bytes, delivered: Promise.resolve(false) };
        }

        const delivered = fetch(url, {
            method: 'POST',
            headers: claimHeaders(),
            body: json,
            credentials: 'same-origin',
            keepalive: true,
        }).then(
            (response) => response.ok,
            // Deliberately unreported beyond `false`, see "What the send functions report".
            () => false,
        );

        return { sent: true, bytes, delivered };
    } catch (error) {
        // JSON.stringify (a cyclic or BigInt claim), the XSRF read or a synchronous fetch
        // throw: nothing was sent, and the cause is returned rather than lost.
        return { sent: false, reason: 'threw', error, delivered: Promise.resolve(false) };
    }
}

/**
 * The headers every claim-carrying POST sends, including the identify path's
 * (resources/js/utils/deviceIdentity.ts), so the CSRF header cannot drift between them.
 */
export function claimHeaders(): Record<string, string> {
    return {
        'content-type': 'application/json',
        // The encrypted cookie value, which is the only form ValidateCsrfToken
        // decrypts before comparing — see resources/js/utils/xsrf.ts.
        'X-XSRF-TOKEN': xsrfToken(),
        accept: 'application/json',
    };
}

export const TRANSPORT_LIMITS = { maxPayloadBytes: MAX_PAYLOAD_BYTES } as const;

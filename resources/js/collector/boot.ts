/**
 * The optional boot entry, for hosts without a single-page application (Blade, Twig, plain
 * HTML): one call from the page's own script starts the collection on the pages that ask for it.
 *
 * ```html
 * <body data-fingerprint-purpose="signin"
 *       data-fingerprint-challenge-url="/security/fingerprint/challenge"
 *       data-fingerprint-claims-url="/security/fingerprint/claims">
 * ```
 *
 * ```js
 * import('@device-id/collector/boot').then(({ initFingerprint }) => void initFingerprint());
 * ```
 *
 * | `<body>` attribute | meaning | default |
 * |---|---|---|
 * | `data-fingerprint-purpose` | the decision this page feeds (`signin`, `register`, `vote`, ...); NO attribute, NO collection | none |
 * | `data-fingerprint-challenge-url` | where the single-use challenge is requested | `/security/fingerprint/challenge` |
 * | `data-fingerprint-claims-url` | where the envelopes are posted | `/security/fingerprint/claims` |
 *
 * The same three values can be passed as `initFingerprint({ purpose, challengeUrl, claimsUrl })`;
 * an explicit option wins over the attribute. The purpose list is the host's: the collector
 * passes the string on and the server's challenge endpoint refuses one it does not know.
 *
 * The collector does not run on catalogue pages: it is not telemetry, and a price page does not
 * need a device decision. Register, sign in, password reset and account actions are the surfaces
 * where the verdict is used.
 *
 * ## Once per tab per purpose
 *
 * A `sessionStorage` marker keeps a visitor who clicks around the sign-in form from spending a
 * challenge per navigation. The marker is KEPT when the server answered (collected and sent, or
 * refused with a 4xx, which a retry would only repeat) and REMOVED when the attempt failed for a
 * reason that may pass (no network, a 5xx, a request that could not be started), so the next page
 * load tries again instead of leaving the tab unprotected for good. Where storage is blocked
 * (some private modes) the visitor is still protected; the collection simply runs once per
 * navigation instead of once per tab.
 */

import { collectAndSendDetailed, type CollectAndSendOutcome } from './index';
import type { CollectionPurpose } from './protocol';

/** The prefix of the once-per-tab marker in `sessionStorage`. */
export const BOOT_MARKER_PREFIX = 'device-id:fp:';

export interface BootOptions {
    /** The decision this page feeds. Falls back to `data-fingerprint-purpose` on `<body>`. */
    readonly purpose?: CollectionPurpose;
    /** Falls back to `data-fingerprint-challenge-url`, then the collector default. */
    readonly challengeUrl?: string;
    /** Falls back to `data-fingerprint-claims-url`, then the collector default. */
    readonly claimsUrl?: string;
}

/** Whether a failed attempt is worth repeating on the next page load. */
function isRetryable(outcome: CollectAndSendOutcome): boolean {
    switch (outcome.status) {
        case 'sent':
            return false;
        case 'no-challenge':
            // A refused challenge (4xx: unknown purpose, rate limit, CSRF) would be refused again.
            return outcome.challenge.reason === 'network' || (outcome.challenge.reason === 'http' && (outcome.challenge.status ?? 0) >= 500);
        case 'send-failed':
            return outcome.send.sent === false && outcome.send.reason !== 'oversize';
        case 'collect-failed':
        case 'unsupported':
            return false;
    }
}

const readAttribute = (name: 'fingerprintPurpose' | 'fingerprintChallengeUrl' | 'fingerprintClaimsUrl'): string | undefined => {
    const value = document.body?.dataset?.[name];

    return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
};

/**
 * Start the collection if this page asks for one. Resolves with the collector's outcome, or
 * `null` when the page asks for nothing or this tab already reported for the purpose. Never
 * rejects and never throws.
 */
export async function initFingerprint(options: BootOptions = {}): Promise<CollectAndSendOutcome | null> {
    if (typeof document === 'undefined') {
        return null;
    }

    const purpose = options.purpose ?? readAttribute('fingerprintPurpose');
    if (!purpose) {
        return null;
    }

    const marker = `${BOOT_MARKER_PREFIX}${purpose}`;
    try {
        if (sessionStorage.getItem(marker)) return null;
        sessionStorage.setItem(marker, '1');
    } catch {
        // Storage refused: report once per navigation instead of once per tab.
    }

    let outcome: CollectAndSendOutcome | null = null;
    try {
        outcome = await collectAndSendDetailed(
            purpose,
            options.challengeUrl ?? readAttribute('fingerprintChallengeUrl'),
            options.claimsUrl ?? readAttribute('fingerprintClaimsUrl'),
        );
    } catch {
        // `collectAndSendDetailed` never rejects by contract; a surprise must still not reach the page.
    }

    if (outcome === null || isRetryable(outcome)) {
        try {
            sessionStorage.removeItem(marker);
        } catch {
            // Nothing was stored.
        }
    }

    return outcome;
}

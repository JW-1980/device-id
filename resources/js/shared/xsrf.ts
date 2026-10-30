/**
 * The CSRF token for a hand-written `fetch()`, read at the moment of the call.
 *
 * Send it as `'X-XSRF-TOKEN': xsrfToken()` — the header name matters, see below.
 *
 * Why not `<meta name="csrf-token">`: `app.blade.php` writes that tag once, into
 * the first HTML response. Everything after that is Inertia swapping page JSON
 * into the same document, so the tag is never rewritten. Signing in through the
 * Inertia login form (or any other `session()->regenerate()` /
 * `regenerateToken()` answered without a full reload — the two-factor
 * challenge, sign-out, admin impersonation start/stop) rotates
 * the session token, and every caller that still sent the tag's value got 419.
 * `fetch()` does not reject on 419, so most of those callers failed silently.
 *
 * The `XSRF-TOKEN` cookie does not have that problem: Laravel's
 * ValidateCsrfToken middleware re-issues it on every web response, with the
 * token the session holds AFTER the request was handled, so the redirect that
 * follows a sign-in already carries the rotated value. It is the same source
 * the shared axios client (bootstrap.ts) and Inertia's router use.
 *
 * The cookie holds the token ENCRYPTED (EncryptCookies runs in the web group),
 * which is why it must travel as `X-XSRF-TOKEN`: that is the one header
 * ValidateCsrfToken decrypts before comparing. The same value in
 * `X-CSRF-TOKEN` or a `_token` body field is compared verbatim and refused.
 *
 * Returns '' when there is no document (SSR, a worker) or no such cookie; the
 * request then carries no usable token and the server answers 419, which the
 * caller must handle like any other failed response.
 */
export const XSRF_COOKIE_NAME = 'XSRF-TOKEN';

export function xsrfToken(): string {
    if (typeof document === 'undefined') {
        return '';
    }

    const prefix = `${XSRF_COOKIE_NAME}=`;

    for (const part of document.cookie.split(';')) {
        const cookie = part.trim();

        if (!cookie.startsWith(prefix)) {
            continue;
        }

        // Laravel URL-encodes the cookie value (the encrypted payload is base64,
        // so `=` arrives as `%3D`); axios decodes it the same way.
        try {
            return decodeURIComponent(cookie.slice(prefix.length));
        } catch {
            // A malformed escape cannot be a token the server issued.
            return '';
        }
    }

    return '';
}

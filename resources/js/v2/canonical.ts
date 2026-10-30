/**
 * Deterministic serialisation and hashing for the fingerprint claim set.
 *
 * ## Why this file exists rather than `JSON.stringify(sortedJson)`
 *
 * Three concrete ways a naive canonicalisation is wrong, each of which silently
 * merges two different devices into one value:
 *
 * 1. **Types collide.** `JSON.stringify({a: 1})` and `JSON.stringify({a: "1"})`
 *    produce different strings, but a hand-rolled serialiser that does
 *    `String(value)` produces the same one. A device reporting `hardwareConcurrency`
 *    as the number 1 and another reporting it as the string "1" would then share a
 *    fingerprint.
 * 2. **Nested objects are not sorted.** `Object.keys(x).sort()` sorts the top level
 *    only. Two devices whose nested `webgl` objects list the same extensions in a
 *    different order would hash identically if the inner object is not sorted too.
 * 3. **Undefined and null are indistinguishable.** `JSON.stringify({a: undefined})`
 *    yields `{}`, so a probe that failed and a probe that returned null are the
 *    same claim. Since the whole design treats "unavailable" and "absent" as
 *    meaningful, that difference has to survive.
 *
 * So every value is **type-tagged** before it is written, keys are sorted
 * recursively, and arrays keep their order (because array order is a signal in
 * several probes — font lists, voice lists, extension lists).
 *
 * ## Why the hash is salted
 *
 * No mainstream collector salts, and two of them ship a 32-bit hash as "the
 * fingerprint" — a four-billion-value space, so a full precomputation is a weekend
 * of GPU time and any device can be looked up. The salt arrives from the server in
 * the challenge response and rotates weekly, so a harvested fingerprint stops
 * working and the value is not a durable cross-session identifier.
 */

/** A probe's outcome. Never a bare value: "unavailable" must be distinguishable. */
export type ProbeResult<T> =
    | { readonly state: 'ok'; readonly value: T }
    | { readonly state: 'unavailable'; readonly reason: string }
    | { readonly state: 'error'; readonly name: string };

export const ok = <T>(value: T): ProbeResult<T> => ({ state: 'ok', value });
export const unavailable = <T>(reason: string): ProbeResult<T> => ({ state: 'unavailable', reason });
export const failed = <T>(error: unknown): ProbeResult<T> => ({
    state: 'error',
    name: error instanceof Error ? error.name : 'Error',
});

/**
 * Run a SYNCHRONOUS probe, converting any throw into a tagged error result.
 *
 * A throwing probe must not propagate: it would abort the whole collection and
 * take the healthy probes down with it, and the exception type alone often
 * fingerprints the engine more than the probe it interrupted.
 *
 * There is a separate `probeAsync` rather than one function that might return a
 * promise, because a sync probe that can return a promise makes every caller
 * handle a union it will never need. The split also keeps `collectIntegrity`
 * fully synchronous, which is what lets it finish inside one microtask and be
 * aborted cheaply.
 *
 * `label` is accepted for call-site readability in stack traces and is otherwise
 * unused: it is a build-time constant, so it never reaches the payload.
 */
export function probe<T>(label: string, fn: () => T): ProbeResult<T> {
    void label;
    try {
        return ok(fn());
    } catch (error) {
        return failed<T>(error);
    }
}

/** Run an ASYNCHRONOUS probe with the same contract. */
export function probeAsync<T>(label: string, fn: () => Promise<T>): Promise<ProbeResult<T>> {
    void label;
    let result: Promise<T>;
    try {
        result = fn();
    } catch (error) {
        return Promise.resolve(failed<T>(error));
    }

    return result.then(
        (value) => ok<T>(value),
        (error: unknown) => failed<T>(error),
    );
}

/** A tagged result as a plain value, or null when it is not `ok`. */
export function unwrap<T>(result: ProbeResult<T> | undefined): T | null {
    return result && result.state === 'ok' ? result.value : null;
}

/** Recursively sorts object keys and type-tags every leaf. */
export function canonicalise(value: unknown): string {
    if (value === undefined) return 'u';
    if (value === null) return 'n';
    if (value === true) return 'b1';
    if (value === false) return 'b0';

    const type = typeof value;
    if (type === 'number') {
        // Object.is distinguishes -0 from 0, and NaN from everything. Skipping that
        // would merge a device reporting -0 with one reporting 0, which happens
        // often enough in a canvas geometry probe to matter.
        if (Number.isNaN(value)) return 'd:NaN';
        if (Object.is(value, -0)) return 'd:-0';
        if (!Number.isFinite(value)) return 'd:' + String(value);
        return 'd:' + String(value);
    }
    if (type === 'string') return 's:' + (value as string);
    if (type === 'bigint') return 'g:' + String(value);
    if (type === 'symbol') return 'y:' + String(value);
    if (type === 'function') return 'f';

    if (Array.isArray(value)) {
        // Order is preserved: several probes return ordered lists where the order
        // IS the signal (font enumeration order, TTS voice order, extension list).
        return '[' + value.map(canonicalise).join(',') + ']';
    }

    const entries = Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => JSON.stringify(key) + ':' + canonicalise((value as Record<string, unknown>)[key]));

    return '{' + entries.join(',') + '}';
}

/** SHA-256, hex encoded. Throws where the platform has no SubtleCrypto (http origins). */
export async function sha256Hex(input: string): Promise<string> {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) {
        throw new Error('SubtleCrypto is unavailable; a secure context is required');
    }

    const bytes = new TextEncoder().encode(input);
    const digest = await subtle.digest('SHA-256', bytes);

    let out = '';
    for (const byte of new Uint8Array(digest)) {
        out += byte.toString(16).padStart(2, '0');
    }
    return out;
}

/**
 * The digest of a canonical claim set.
 *
 * ## Why there is no salt argument any more
 *
 * This used to take a rotating server-held salt and was documented as the client's
 * "keyed hash", with the reasoning that an unkeyed digest would let an attacker
 * precompute other people's fingerprints.
 *
 * That reasoning was about a property the value never had, and the server never used it
 * as one. `ClientClaimsEnvelope` has no `sig` field: freshness comes from the
 * single-use challenge token and session binding from the device-cookie compare, both
 * server-side and both stronger than anything a client holding its own key can prove. The
 * salt never reached the server, so it never keyed anything the server could check, and
 * a rainbow table was never the threat — the identifier is `DeviceKeyDeriver's scoped
 * HMAC, computed server-side, and that is what has to resist precomputation.
 *
 * What this is now: an UNKEYED canonical hash, used to cross-reference the two envelopes
 * of one visit (tier 1 and tier 2) and for debugging. It is explicitly not a security
 * value and nothing trusts it.
 *
 * ## Canonicalise before hashing, always
 *
 * The tagged encoding (`d:` / `s:` / `b1`) is what makes two structurally different JSON
 * values that are semantically identical produce the same string. `JSON.stringify` does
 * not: key order follows insertion order, so two probes reporting the same facts in a
 * different order would hash differently and one device would look like two.
 */
export async function claimDigest(claims: unknown): Promise<string> {
    return sha256Hex(canonicalise(claims));
}
/** FNV-1a, 32 bit. Only for non-security keys inside a single page load. */
export function fnv1a32(input: string): string {
    let hash = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
        hash ^= input.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
}

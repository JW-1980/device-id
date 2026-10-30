/**
 * Ambient declarations for browser APIs that are shipped but not yet in the
 * TypeScript DOM library.
 *
 * ## Why this file exists
 *
 * Every declaration here is a real, shipped API that `lib.dom.d.ts` has not caught
 * up with. The alternatives are all worse:
 *
 * - `as unknown as X` scattered at each call site — which is what the code looked
 *   like before this file, and which hides real type errors in the expressions it is
 *   wrapped around.
 * - `// @ts-ignore` — suppresses the line above *and* the next one, permanently.
 * - Declaring a global augmentation of `Navigator`/`Screen`/`Uint8Array` — cleaner at
 *   the call site, but it changes the shape of the platform types for the entire
 *   project, including code that must work in browsers where these APIs do not exist.
 *   That is a much bigger promise to make than "this module knows about them".
 *
 * A local, module-scoped declaration is the smallest honest statement: *this code*
 * knows these APIs exist, and the optionality is expressed in the types themselves
 * so every call site is forced to handle absence.
 *
 * ## Optionality is not decoration
 *
 * The fingerprint code runs on every browser the project supports, including ones
 * where these APIs are absent. Firefox and Safari do not implement
 * `navigator.userAgentData` at all. Typing it as non-optional would produce code
 * that compiles and then throws in exactly the browsers the absence check was
 * written to protect.
 */

/** `navigator.userAgentData` (UA Client Hints). Chromium-only in practice. */
export interface FingerprintUserAgentData {
    readonly brands: ReadonlyArray<{ readonly brand: string; readonly version: string }>;
    readonly mobile: boolean;
    readonly platform: string;
    getHighEntropyValues(hints: readonly string[]): Promise<Record<string, unknown>>;
}

export interface NavigatorWithUserAgentData extends Navigator {
    readonly userAgentData?: FingerprintUserAgentData;
}

/**
 * `Screen.availLeft` / `availTop`.
 *
 * Present in every engine and absent from `lib.dom.d.ts`. The offsets of the
 * available area from the screen origin, which is what reveals a multi-monitor
 * arrangement.
 */
export interface ScreenWithAvail extends Screen {
    readonly availLeft?: number;
    readonly availTop?: number;
}

/**
 * The ES2026 `Uint8Array` base64/hex conversions.
 *
 * Declared on a local record rather than on `Uint8Array` itself, because augmenting
 * a global interface for a feature-stage API is the kind of change that outlives
 * the code that needed it.
 */
export interface Uint8ArrayWithBase64 {
    fromBase64?: (input: string, options?: { alphabet?: string; lastChunkHandling?: string }) => Uint8Array;
    toBase64?: (options?: { alphabet?: string; omitPadding?: boolean }) => string;
    setFromBase64?: (input: string, options?: { alphabet?: string }) => Uint8Array;
    toHex?: () => string;
}

/** The `Intl` options that accept a runtime string rather than a fixed union. */
export type LooseIntlOptions = Omit<Intl.DateTimeFormatOptions, 'calendar'> & { calendar?: string };


/**
 * Read a possibly-absent member of an object, without a cast at the call site.
 *
 * Deliberately not generic in its key type: every caller in this subsystem passes a
 * literal property name, and constraining the key to `string` keeps the return type
 * honest (`unknown`, so the caller narrows) without needing a cast at each use.
 */
export const hasMember = (target: unknown, key: string): unknown =>
    (target as Record<string, unknown> | null | undefined)?.[key];

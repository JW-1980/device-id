/**
 * Reads that must produce the same shape in TWO realms: the page (`value-probes.ts`) and a
 * dedicated worker (`scope.worker.ts`).
 *
 * ## Why this is its own module
 *
 * The window-versus-worker comparison (`workerScope`) is only meaningful if both sides run
 * the SAME code. Two hand-maintained copies would drift, and a drift would look exactly like
 * the thing the comparison exists to find: a spoofer that patched one realm and not the
 * other. So the snapshot, the engine marks and the classifier live here once, and both
 * realms import them.
 *
 * The constraint that follows: **nothing in this file may touch `document` or `window`**,
 * at module scope or inside a function. It is evaluated in a `DedicatedWorkerGlobalScope`,
 * where neither exists; everything is reached through `globalThis`. It imports nothing but
 * types, so the worker chunk stays small.
 *
 * ## Prior art, and what is done differently
 *
 * CreepJS (`src/worker/index.ts`, catalogue §15) compares `userAgent`, `platform`,
 * `hardwareConcurrency` and `deviceMemory` between the page and a worker, and derives the
 * engine from `(-1).toFixed(-1)` message length plus the source length of `[].constructor`
 * (80 V8 / 58 SpiderMonkey / 77 JavaScriptCore). Three differences here, each deliberate:
 *
 * - The client does not DECIDE anything. It reports raw marks and both snapshots; the
 *   server compares them and re-derives the engine from the marks. A client-side verdict is
 *   one assignment away from `false`.
 * - The engine is classified from STRUCTURAL marks (which own properties an `Error`
 *   instance carries, and the stack-frame syntax), not from the sum of two lengths. A sum
 *   is a single number a spoofer can hit by accident or on purpose, and an unseen engine
 *   lands on an arbitrary value; an own-property set names its engine (`lineNumber` is
 *   SpiderMonkey's, `sourceURL` is JavaScriptCore's). The message length is still
 *   reported, as a mark the server may use, but nothing here depends on it.
 * - `language` IS collected in both realms. CreepJS skips it because of a Chrome bug, and
 *   its own check is unreachable code (catalogue §14: an early `return`, and an array
 *   compared with a string). Collecting the value costs nothing; whether a mismatch is
 *   evidence is the server's decision, which can then be made from data.
 */

/** The engine family, as the client classifies it. The server does not trust this. */
export type EngineName = 'v8' | 'spidermonkey' | 'jsc' | 'unknown';

/** Syntax of the first stack frame: `    at fn (url)` (V8) or `fn@url` (SpiderMonkey, JSC). */
export type StackShape = 'at' | 'at-sign' | 'none' | 'other';

/** The raw marks the classification is derived from. All four are sent. */
export interface EngineMarks {
    /** `Object.getOwnPropertyNames(new Error('x')).sort().join(',')`. */
    readonly errorOwnProps: string;
    readonly stackShape: StackShape;
    /** `.message.length` of the RangeError from `(-1).toFixed(-1)`; -1 if it did not throw. */
    readonly toFixedMessageLength: number;
    /** `typeof globalThis.InternalError === 'function'` — a SpiderMonkey-only global. */
    readonly internalError: boolean;
}

/** `tier1.engineIdentity` on the wire. */
export interface EngineIdentity extends EngineMarks {
    readonly engine: EngineName;
}

/** One realm's view of the device. The window and the worker use IDENTICAL keys. */
export interface ScopeSnapshot {
    readonly userAgent: string | null;
    readonly platform: string | null;
    readonly hardwareConcurrency: number | null;
    readonly deviceMemory: number | null;
    readonly language: string | null;
    readonly languages: string | null;
    readonly timeZone: string | null;
    readonly locale: string | null;
    readonly tzOffset: number | null;
    readonly uaPlatform: string | null;
    readonly uaMobile: boolean | null;
    readonly uaBrands: string | null;
    readonly webglVendor: string | null;
    readonly webglRenderer: string | null;
    readonly currencyCount: number | null;
    readonly engine: EngineName;
    /**
     * `fnv1a32` of the geometry-only canvas scene (`canvasRealmHash`) as this realm
     * rasterises and reads it back; null when the realm has no 2D canvas or its two reads
     * disagree (a randomised read-back).
     */
    readonly canvasHash: string | null;
}

/** The unmasked WebGL identity strings, or nulls. */
export interface WebGlIdentity {
    readonly vendor: string | null;
    readonly renderer: string | null;
}

/** The message the worker replies with. Anything else is rejected by `sanitiseReply`. */
export const SCOPE_REPLY_KIND = 'nc-scope';

/** The worker's reply to `{ ask: 'spin', ms }`: `{ kind: 'nc-spin', iterations }`. */
export const SPIN_REPLY_KIND = 'nc-spin';

/** The longest spin a worker will run, whatever it is asked: a bound on a hostile request. */
export const SPIN_MAX_MS = 200;

/**
 * The spin duration a message asks for, or null when it is not a spin request. Clamped to
 * 0..`SPIN_MAX_MS`; a non-finite or non-numeric `ms` is 0 (a "ready" ping).
 */
export function spinRequestMs(message: unknown): number | null {
    if (typeof message !== 'object' || message === null || (message as { ask?: unknown }).ask !== 'spin') {
        return null;
    }
    const ms = (message as { ms?: unknown }).ms;

    return typeof ms === 'number' && Number.isFinite(ms) ? Math.min(SPIN_MAX_MS, Math.max(0, ms)) : 0;
}

/** The iteration count from a spin reply, or null when the reply is not one. */
export function spinIterations(reply: unknown): number | null {
    if (typeof reply !== 'object' || reply === null || (reply as { kind?: unknown }).kind !== SPIN_REPLY_KIND) {
        return null;
    }
    const iterations = (reply as { iterations?: unknown }).iterations;

    return typeof iterations === 'number' && Number.isInteger(iterations) && iterations >= 0 ? iterations : null;
}

/** The message text of the probe error. Chosen with no `@` and no ` at ` in it. */
const PROBE_MESSAGE = 'x';

const ENGINES: readonly EngineName[] = ['v8', 'spidermonkey', 'jsc', 'unknown'];

/** Run `fn`; any throw becomes `null`. Every field of a snapshot is read through this. */
function guarded<T>(fn: () => T | null): T | null {
    try {
        return fn();
    } catch {
        return null;
    }
}

const asString = (value: unknown): string | null => (typeof value === 'string' ? value : null);
const asNumber = (value: unknown): number | null => (typeof value === 'number' && Number.isFinite(value) ? value : null);
const asBoolean = (value: unknown): boolean | null => (typeof value === 'boolean' ? value : null);

/**
 * Classify the engine from its marks.
 *
 * The order matters and is the documented contract the server re-implements:
 *
 * 1. `spidermonkey` — an `Error` instance owns `lineNumber`, `columnNumber` or `fileName`,
 *    or the `InternalError` global exists. All four are SpiderMonkey extensions.
 * 2. `jsc` — an `Error` instance owns `sourceURL`, or both `line` and `column`.
 *    JavaScriptCore's own-property extensions.
 * 3. `v8` — the first frame is written `at …` AND `stack` is an own property (V8 installs
 *    it per instance; SpiderMonkey has it as an accessor on `Error.prototype`).
 * 4. Otherwise `unknown`. Never a guess: an engine that matches none of the above is
 *    reported as such, and the raw marks travel with it.
 */
export function classifyEngine(marks: Pick<EngineMarks, 'errorOwnProps' | 'stackShape' | 'internalError'>): EngineName {
    const props = new Set(marks.errorOwnProps.split(',').filter((name) => name !== ''));

    if (props.has('lineNumber') || props.has('columnNumber') || props.has('fileName') || marks.internalError) {
        return 'spidermonkey';
    }
    if (props.has('sourceURL') || (props.has('line') && props.has('column'))) {
        return 'jsc';
    }
    if (marks.stackShape === 'at' && props.has('stack')) {
        return 'v8';
    }

    return 'unknown';
}

/**
 * The first stack frame's syntax.
 *
 * V8 starts `stack` with a header line (`Error: x`) and writes frames as `    at fn (url)`.
 * SpiderMonkey and JavaScriptCore write no header and frames as `fn@url:line:col`. So the
 * header line, when present, is skipped, and the first remaining non-empty line decides.
 * No stack at all, or a stack with no frame line (V8 with `Error.stackTraceLimit = 0`),
 * is `none`.
 */
export function stackShapeOf(stack: unknown, name = 'Error', message = PROBE_MESSAGE): StackShape {
    if (typeof stack !== 'string') {
        return 'none';
    }

    const header = `${name}: ${message}`;
    const first = stack
        .split('\n')
        .find((line) => line.trim() !== '' && line.trim() !== header);

    if (first === undefined) {
        return 'none';
    }
    if (/^\s+at\s/.test(first)) {
        return 'at';
    }
    if (first.includes('@')) {
        return 'at-sign';
    }

    return 'other';
}

/** Read the four marks in the current realm. Never throws: each mark is guarded. */
export function engineMarks(): EngineMarks {
    const sample = guarded(() => new Error(PROBE_MESSAGE));

    const errorOwnProps = guarded(() => (sample ? Object.getOwnPropertyNames(sample).sort().join(',') : null)) ?? '';
    const stackShape = guarded(() => stackShapeOf(sample?.stack)) ?? 'none';

    let toFixedMessageLength = -1;
    try {
        (-1).toFixed(-1);
    } catch (error) {
        // Read structurally: a RangeError from another realm is not `instanceof Error` here.
        const message = typeof error === 'object' && error !== null ? (error as { message?: unknown }).message : undefined;
        toFixedMessageLength = typeof message === 'string' ? message.length : -1;
    }

    const internalError = guarded(() => typeof (globalThis as { InternalError?: unknown }).InternalError === 'function') ?? false;

    return { errorOwnProps, stackShape, toFixedMessageLength, internalError };
}

/** The marks plus the client's own classification of them. */
export function engineIdentityOf(): EngineIdentity {
    const marks = engineMarks();

    return {
        engine: classifyEngine(marks),
        errorOwnProps: marks.errorOwnProps,
        stackShape: marks.stackShape,
        toFixedMessageLength: marks.toFixedMessageLength,
        internalError: marks.internalError,
    };
}

/**
 * `userAgentData.brands` as `brand/version` strings, sorted, joined by `,`, with the GREASE
 * brand removed.
 *
 * GREASE ("Not)A;Brand", "Not_A Brand", ...) is a deliberately random entry Chromium adds so
 * servers do not hard-code the list. Its spelling and version rotate between releases, so
 * leaving it in would make the value churn for a reason unrelated to the device, and the
 * two realms could legitimately disagree on it across an update. Recognised the way
 * CreepJS does (catalogue §14): the name contains both "not" and "brand", case-insensitive.
 * Sorted because the brand ORDER is also randomised per release.
 */
export function formatBrands(brands: unknown): string | null {
    if (!Array.isArray(brands)) {
        return null;
    }

    return brands
        .filter((entry): entry is { brand: string; version: string } =>
            typeof entry === 'object' && entry !== null &&
            typeof (entry as { brand?: unknown }).brand === 'string' &&
            typeof (entry as { version?: unknown }).version === 'string')
        .filter(({ brand }) => !(/not/i.test(brand) && /brand/i.test(brand)))
        .map(({ brand, version }) => `${brand}/${version}`)
        .sort()
        .join(',');
}

/**
 * The UNMASKED vendor and renderer of a WebGL context, through `WEBGL_debug_renderer_info`.
 * Null when there is no context or no extension: the masked `VENDOR`/`RENDERER` strings are
 * a different quantity ("WebKit", "WebKit WebGL") and are deliberately not substituted.
 */
export function unmaskedWebGl(gl: WebGLRenderingContext | WebGL2RenderingContext | null | undefined): WebGlIdentity {
    if (!gl) {
        return { vendor: null, renderer: null };
    }

    const debug = guarded(() => gl.getExtension('WEBGL_debug_renderer_info'));
    if (!debug) {
        return { vendor: null, renderer: null };
    }

    return {
        vendor: guarded(() => asString(gl.getParameter(debug.UNMASKED_VENDOR_WEBGL))),
        renderer: guarded(() => asString(gl.getParameter(debug.UNMASKED_RENDERER_WEBGL))),
    };
}

/** The navigator shape both realms share (`Navigator` and `WorkerNavigator`). */
interface RealmNavigator {
    readonly userAgent?: unknown;
    readonly platform?: unknown;
    readonly hardwareConcurrency?: unknown;
    readonly deviceMemory?: unknown;
    readonly language?: unknown;
    readonly languages?: unknown;
    readonly userAgentData?: { readonly platform?: unknown; readonly mobile?: unknown; readonly brands?: unknown };
}

/**
 * This realm's snapshot. Every field is read in its own guard and is null when it cannot
 * be read, so one throwing getter cannot take the others down. Never throws.
 *
 * `tzOffset` is read for a FIXED date (15 January 2026), not "now": the current offset
 * changes at every DST transition, which would make the claim differ between two loads a
 * day apart for a reason unrelated to the device.
 */
export function scopeSnapshot(webgl: WebGlIdentity, canvasHash: string | null): ScopeSnapshot {
    const nav = guarded(() => (globalThis as { navigator?: RealmNavigator }).navigator ?? null);
    const resolved = guarded(() => Intl.DateTimeFormat().resolvedOptions());
    const uad = guarded(() => nav?.userAgentData ?? null);

    return {
        userAgent: guarded(() => asString(nav?.userAgent)),
        platform: guarded(() => asString(nav?.platform)),
        hardwareConcurrency: guarded(() => asNumber(nav?.hardwareConcurrency)),
        deviceMemory: guarded(() => asNumber(nav?.deviceMemory)),
        language: guarded(() => asString(nav?.language)),
        languages: guarded(() =>
            nav?.languages === undefined || nav.languages === null
                ? null
                : Array.from(nav.languages as Iterable<unknown>).join(','),
        ),
        timeZone: guarded(() => asString(resolved?.timeZone)),
        locale: guarded(() => asString(resolved?.locale)),
        tzOffset: guarded(() => asNumber(new Date(2026, 0, 15).getTimezoneOffset())),
        uaPlatform: guarded(() => asString(uad?.platform)),
        uaMobile: guarded(() => asBoolean(uad?.mobile)),
        uaBrands: guarded(() => (uad ? formatBrands(uad.brands) : null)),
        webglVendor: webgl.vendor,
        webglRenderer: webgl.renderer,
        currencyCount: guarded(() =>
            typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('currency').length : null,
        ),
        engine: guarded(() => classifyEngine(engineMarks())) ?? 'unknown',
        canvasHash,
    };
}

/**
 * Validate a worker reply and rebuild it field by field.
 *
 * The reply crosses a realm boundary, so it is external input (CLAUDE.md Chapter 5,
 * "Validation"): every field is re-typed here, a wrongly-typed field becomes null, and a
 * reply that is not `{ kind: 'nc-scope', snapshot: {...} }` is rejected outright (null),
 * which the caller reports as `unavailable`. Nothing the worker sends reaches the claim set
 * without passing through this.
 */
export function sanitiseReply(reply: unknown): ScopeSnapshot | null {
    if (typeof reply !== 'object' || reply === null) {
        return null;
    }
    const { kind, snapshot } = reply as { kind?: unknown; snapshot?: unknown };
    if (kind !== SCOPE_REPLY_KIND || typeof snapshot !== 'object' || snapshot === null) {
        return null;
    }

    const s = snapshot as Record<string, unknown>;
    const engine = ENGINES.includes(s.engine as EngineName) ? (s.engine as EngineName) : 'unknown';

    return {
        userAgent: asString(s.userAgent),
        platform: asString(s.platform),
        hardwareConcurrency: asNumber(s.hardwareConcurrency),
        deviceMemory: asNumber(s.deviceMemory),
        language: asString(s.language),
        languages: asString(s.languages),
        timeZone: asString(s.timeZone),
        locale: asString(s.locale),
        tzOffset: asNumber(s.tzOffset),
        uaPlatform: asString(s.uaPlatform),
        uaMobile: asBoolean(s.uaMobile),
        uaBrands: asString(s.uaBrands),
        webglVendor: asString(s.webglVendor),
        webglRenderer: asString(s.webglRenderer),
        currencyCount: asNumber(s.currencyCount),
        engine,
        canvasHash: typeof s.canvasHash === 'string' && /^[0-9a-f]{8}$/.test(s.canvasHash) ? s.canvasHash : null,
    };
}

// ---------------------------------------------------------------------------
// canvasRealm (note 22, M2): the same scene rasterised in the page and in the worker
// ---------------------------------------------------------------------------

/** The scene's canvas size. */
export const CANVAS_REALM_WIDTH = 160;
export const CANVAS_REALM_HEIGHT = 64;

/** The members of a 2D context the scene uses; both `CanvasRenderingContext2D` and the worker's `OffscreenCanvasRenderingContext2D` have them. */
export type RealmContext2D = Pick<
    CanvasRenderingContext2D,
    'fillStyle' | 'strokeStyle' | 'lineWidth' | 'globalCompositeOperation' | 'fillRect' | 'beginPath' | 'arc' |
    'closePath' | 'fill' | 'moveTo' | 'bezierCurveTo' | 'stroke' | 'getImageData'
>;

/**
 * FNV-1a, 32 bit, over raw bytes. The same function as `canonical.ts` `fnv1a32` applied to
 * a string of the same byte values (each char code < 256), without building that string;
 * kept here so the worker bundle does not pull in the canonicaliser.
 */
export function fnv1a32Bytes(bytes: ArrayLike<number>): string {
    let hash = 0x811c9dc5;
    for (let i = 0; i < bytes.length; i++) {
        hash ^= bytes[i] as number;
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * Draw the scene: GEOMETRY ONLY — fills, an arc, a bezier stroke and a multiply-composited
 * rectangle at fractional coordinates. No text: a worker has no document fonts, and the
 * review (notes/22) required a scene whose rasterisation cannot depend on font fallback.
 */
function drawRealmScene(context: RealmContext2D): void {
    context.fillStyle = 'rgb(240,240,236)';
    context.fillRect(0, 0, CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT);

    context.fillStyle = 'rgba(30,90,200,0.7)';
    context.beginPath();
    context.arc(40.5, 32.25, 24.5, 0, Math.PI * 1.75);
    context.closePath();
    context.fill();

    context.strokeStyle = 'rgb(200,40,40)';
    context.lineWidth = 2.3;
    context.beginPath();
    context.moveTo(2.5, 60.5);
    context.bezierCurveTo(50.25, -10.5, 110.75, 74.5, 157.5, 3.5);
    context.stroke();

    context.globalCompositeOperation = 'multiply';
    context.fillStyle = 'rgba(20,160,90,0.55)';
    context.fillRect(70.5, 10.25, 60.5, 40.75);
    context.globalCompositeOperation = 'source-over';
}

/**
 * The scene's read-back hash in this realm, or null.
 *
 * Why (notes/22 M2): canvas-noise extensions patch `CanvasRenderingContext2D.getImageData`
 * and friends in the PAGE realm; a dedicated worker's `OffscreenCanvas` is a realm their
 * content scripts do not reach. Both realms draw this scene and hash what they read; the
 * server compares the two (`canvas_realm_mismatch`). The client raises no finding.
 *
 * Measured by the review on Chromium 153, Firefox 155 and WebKit 26.6: page and worker
 * rasterise identically (0 differing pixels), with `willReadFrequently` in both realms, which
 * is why the caller must create the context with it.
 *
 * Read twice; two reads that differ mean a randomised read-back (Firefox RFP, per-read noise
 * extensions), whose hash says nothing, so the realm reports null. Never throws.
 */
export function canvasRealmHash(context: RealmContext2D | null | undefined): string | null {
    if (!context) return null;
    try {
        drawRealmScene(context);
        const first = context.getImageData(0, 0, CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT).data;
        const second = context.getImageData(0, 0, CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT).data;
        const size = CANVAS_REALM_WIDTH * CANVAS_REALM_HEIGHT * 4;
        if (first.length !== size || second.length !== size) return null;
        for (let i = 0; i < size; i++) {
            if (first[i] !== second[i]) return null;
        }
        return fnv1a32Bytes(first);
    } catch {
        return null;
    }
}

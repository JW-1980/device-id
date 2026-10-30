/**
 * The dedicated-worker half of the `workerScope` probe (value-probes.ts).
 *
 * ## What it is for
 *
 * A spoofer that rewrites `navigator`, `Intl` or WebGL from a page script or an extension
 * content script reaches the page's realm. A dedicated worker is a separate realm with its
 * own `WorkerNavigator`, its own `Intl` and its own `OffscreenCanvas` WebGL, so page-level
 * patches do not reach it unless the spoofer goes out of its way to inject into every
 * worker too. The window collects the same snapshot after this one replies; the SERVER
 * compares the two. This file decides nothing.
 *
 * Prior art: CreepJS `src/worker/index.ts` (catalogue §15) — service, then shared, then
 * dedicated worker, loaded from its own bundle, and compared on the client. Here: a
 * dedicated worker only (the one every supported engine has, including Safari, which has
 * no SharedWorker on iOS), compared on the server, with the client sending raw values.
 *
 * ## How it is loaded, and why that way
 *
 * `new Worker(new URL('./scope.worker.ts', import.meta.url))` (a classic worker; module in the dev server only, see `createScopeWorker`) in the
 * window. Vite emits this file as its own same-origin chunk, so the existing CSP
 * (`script-src 'self' 'nonce-…'`, no `worker-src`, which therefore falls back to
 * `script-src`) allows it without a change. A `blob:` or `data:` worker URL would need the
 * CSP widened and is deliberately not used.
 *
 * ## Contract with the window
 *
 * - `{ ask: 'spin', ms }` (the `parallelism` probe) busy-loops `ms` (clamped to
 *   `SPIN_MAX_MS`) and replies `{ kind: 'nc-spin', iterations }`; `ms: 0` is a ready ping.
 * - Any other message starts one snapshot; the reply is `{ kind: 'nc-scope', snapshot }`.
 *   The window terminates the worker on the reply.
 * - Never throws. Every field is read in its own guard (`scopeSnapshot`), WebGL included,
 *   and the reply itself is posted in a guard. A worker that cannot reply is caught by the
 *   window's timeout.
 * - No `console.*`, no network, no `importScripts`, no `eval`.
 */

import {
    CANVAS_REALM_HEIGHT,
    CANVAS_REALM_WIDTH,
    canvasRealmHash,
    renderGpuMathOn,
    SCOPE_REPLY_KIND,
    SPIN_REPLY_KIND,
    scopeSnapshot,
    spinRequestMs,
    unmaskedWebGl,
    type WebGlIdentity,
} from './realm';

/**
 * The two members of `DedicatedWorkerGlobalScope` this file uses. The project compiles
 * against the DOM lib (where `self` is a `Window`), not the WebWorker lib, so the scope is
 * described locally rather than by changing the type environment of every other module.
 */
interface WorkerScopeLike {
    addEventListener(type: 'message', listener: (event: { readonly data: unknown }) => void): void;
    postMessage(message: unknown): void;
}

const scope = self as unknown as WorkerScopeLike;

/**
 * This realm's unmasked WebGL identity, from a 1×1 `OffscreenCanvas`: WebGL 2 first, then
 * WebGL 1 on a FRESH canvas (a canvas that refused one context type is not reused), with
 * the same `failIfMajorPerformanceCaveat: false` the window's shared context uses, so both
 * realms ask for the same adapter. The context is lost explicitly once read; the worker is
 * terminated right after anyway.
 */
function workerWebGl(): { readonly identity: WebGlIdentity; readonly gpuMath: { readonly hash: string; readonly precision: string } | null } {
    if (typeof OffscreenCanvas !== 'function') {
        return { identity: { vendor: null, renderer: null }, gpuMath: null };
    }

    const attributes: WebGLContextAttributes = { failIfMajorPerformanceCaveat: false };
    let gl: WebGLRenderingContext | WebGL2RenderingContext | null = null;
    try {
        gl = new OffscreenCanvas(1, 1).getContext('webgl2', attributes);
    } catch {
        gl = null;
    }
    if (!gl) {
        try {
            gl = new OffscreenCanvas(1, 1).getContext('webgl', attributes);
        } catch {
            gl = null;
        }
    }

    const identity = unmaskedWebGl(gl);

    // The same shader render the page runs (`gpuMath`), on this realm's own context: a hook on
    // the page's `readPixels`/`getParameter` that passes the lie battery cannot reach it.
    let gpuMath: { readonly hash: string; readonly precision: string } | null = null;
    if (gl) {
        try {
            const rendered = renderGpuMathOn(gl);
            gpuMath = { hash: rendered.hash, precision: rendered.precision };
        } catch {
            // An unavailable render (no shader support, randomised read-back) is silence for
            // the comparison, and nothing else is worth failing the snapshot for.
            gpuMath = null;
        }
    }

    try {
        gl?.getExtension('WEBGL_lose_context')?.loseContext();
    } catch {
        /* a context that cannot be lost goes with the terminated worker */
    }

    return { identity, gpuMath };
}

/** Arithmetic steps between two clock reads in `spin`. */
const SPIN_BATCH = 1024;

/**
 * Busy-loop for `ms` milliseconds of this worker's own clock and count the work done
 * (the `parallelism` probe, value-probes.ts): the count is how much CPU this worker got while
 * every other worker of the same round was spinning too.
 *
 * The work is integer arithmetic, with the clock read once per `SPIN_BATCH` steps. Counting
 * clock reads instead measured the clock: on a virtual machine `performance.now()` can be a
 * trap into the hypervisor that does not scale with cores, and a 4-core machine read as
 * more than 4.5 cores in up to 8 of 20 runs (Firefox 155, 2026-10-05).
 */
function spin(ms: number): number {
    const end = performance.now() + ms;
    let iterations = 0;
    let state = 1;
    while (performance.now() < end) {
        for (let step = 0; step < SPIN_BATCH; step++) {
            state = (Math.imul(state, 1103515245) + 12345) | 0;
        }
        iterations += SPIN_BATCH;
    }

    // `state` is folded in as 0 or 1 so the loop cannot be optimised away and the count stays
    // a multiple-of-batch number a reviewer can recognise.
    return iterations + (state === 0x7fffffff ? 1 : 0);
}

/**
 * This realm's `canvasRealm` hash (notes/22 M2), from an `OffscreenCanvas` 2D context with
 * `willReadFrequently`, as the page side uses. Null without OffscreenCanvas 2D (Safari before
 * 16.4) or when the two reads disagree.
 */
function workerCanvasHash(): string | null {
    try {
        if (typeof OffscreenCanvas !== 'function') return null;
        const context = new OffscreenCanvas(CANVAS_REALM_WIDTH, CANVAS_REALM_HEIGHT).getContext('2d', { willReadFrequently: true });
        return canvasRealmHash(context);
    } catch {
        return null;
    }
}

scope.addEventListener('message', (event) => {
    const spinMs = spinRequestMs(event?.data);
    if (spinMs !== null) {
        try {
            scope.postMessage({ kind: SPIN_REPLY_KIND, iterations: spin(spinMs) });
        } catch {
            /* the window's timeout covers a reply that cannot be posted */
        }
        return;
    }

    let snapshot = null;
    try {
        const webgl = workerWebGl();
        snapshot = scopeSnapshot(webgl.identity, workerCanvasHash(), webgl.gpuMath);
    } catch {
        // `scopeSnapshot` guards every field and cannot throw; this is the belt to that
        // pair of braces. A null snapshot is rejected by the window as malformed.
        snapshot = null;
    }

    try {
        scope.postMessage({ kind: SCOPE_REPLY_KIND, snapshot });
    } catch {
        /* nothing can be reported from here; the window's timeout covers it */
    }
});

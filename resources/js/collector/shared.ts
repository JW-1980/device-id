/**
 * Resources shared by several probes within ONE collection, created lazily and released
 * when the collection ends.
 *
 * A WebGL context costs 6-12 ms to create (130 ms with a software renderer) and Chromium
 * destroys the oldest live context once sixteen exist, with a console warning. An
 * `AudioContext` starts the output path on first use (about 40 ms cold) and browsers cap
 * the number of live ones. So each is created at most once per collection, handed to
 * every probe that needs it, and released in `releaseShared()`.
 *
 * A dedicated worker (the `workerScope` probe) is not shared, but it is a live resource of
 * the same kind: it is registered with `onRelease()` and terminated here too if it is
 * still running when the collection ends.
 */

export interface SharedWebGl {
    readonly context: WebGLRenderingContext | WebGL2RenderingContext;
    readonly webgl2: boolean;
}

let webgl: SharedWebGl | null | undefined;
let audio: AudioContext | null | undefined;

/** The collection's WebGL context, or null when the engine has none. Never throws. */
export function sharedWebGl(): SharedWebGl | null {
    if (webgl !== undefined) {
        return webgl;
    }

    webgl = null;
    try {
        const canvas = document.createElement('canvas');
        const attributes: WebGLContextAttributes = { failIfMajorPerformanceCaveat: false };
        const gl2 = typeof WebGL2RenderingContext === 'function' ? canvas.getContext('webgl2', attributes) : null;
        if (gl2) {
            webgl = { context: gl2, webgl2: true };
        } else {
            const gl1 = canvas.getContext('webgl', attributes);
            if (gl1) {
                webgl = { context: gl1, webgl2: false };
            }
        }
    } catch {
        webgl = null;
    }

    return webgl;
}

/** The collection's realtime `AudioContext`, or null when the engine has none. Never throws. */
export function sharedAudioContext(): AudioContext | null {
    if (audio !== undefined) {
        return audio;
    }

    audio = null;
    try {
        const Ctor = (window.AudioContext ??
            (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext) as
            | typeof AudioContext
            | undefined;
        audio = Ctor ? new Ctor() : null;
    } catch {
        audio = null;
    }

    return audio;
}

/**
 * Work that must be torn down when the collection ends: currently the `workerScope`
 * probe's dedicated worker. Each entry terminates its worker AND settles the probe that
 * owns it, so a release while the probe is still waiting resolves it at once instead of
 * leaving it to its timeout.
 */
const disposers = new Set<() => void>();

/**
 * Register a teardown to run in `releaseShared()`. Returns the function that unregisters
 * it, which the owner calls when it has already cleaned up by itself.
 */
export function onRelease(dispose: () => void): () => void {
    disposers.add(dispose);

    return () => {
        disposers.delete(dispose);
    };
}

/** How many collections are currently holding the shared resources (`acquireShared`). */
let holders = 0;

/**
 * Hold the shared resources for one collection, and get the function that lets go of them.
 *
 * `collectTier2Block` used to call `releaseShared()` unconditionally when it finished, so two
 * collections in flight at once — the identify path's tier 2 and a sign-in's scheduled tier 2
 * on the same page, or an abandoned identify tier 2 still finishing — released each other's
 * WebGL context, audio context and live worker mid-run. Now each collection acquires a hold,
 * and the resources are released when the LAST hold is let go. The returned function is
 * idempotent: calling it twice releases one hold, once.
 */
export function acquireShared(): () => void {
    holders++;
    let held = true;

    return () => {
        if (!held) return;
        held = false;
        holders = Math.max(0, holders - 1);
        if (holders === 0) releaseShared();
    };
}

/**
 * Release every shared resource NOW, whoever holds it. Safe to call when nothing was created.
 * Collections use `acquireShared()`; this unconditional form is for the diagnostics
 * (`measureProbes`, `measurePhases`) and for tests.
 */
export function releaseShared(): void {
    // Everything is released, so no hold is meaningful any more; a collection that still
    // calls its release function afterwards finds the count at zero (clamped) and releases
    // nothing new.
    holders = 0;
    for (const dispose of [...disposers]) {
        try {
            dispose();
        } catch {
            /* one failed teardown must not keep the others alive */
        }
    }
    disposers.clear();

    if (webgl) {
        try {
            webgl.context.getExtension('WEBGL_lose_context')?.loseContext();
        } catch {
            /* a context that cannot be lost is simply left to the GC */
        }
    }
    webgl = undefined;

    if (audio) {
        try {
            void audio.close().catch(() => undefined);
        } catch {
            /* an already-closed context throws InvalidStateError; nothing to release */
        }
    }
    audio = undefined;
}

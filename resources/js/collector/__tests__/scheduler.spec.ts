/**
 * The deferred scheduler (value-probes.ts `runDeferred`, decision G-D5i of the round-2 fix
 * round): one probe per idle slice, deadline-aware, stepped `fontMetrics`, audio probes
 * last, a bounded `document.fonts.ready` wait, and a partial result on abort.
 *
 * jsdom has no `requestIdleCallback`; these tests install one that hands out a scripted
 * `IdleDeadline`, so the scheduler's decisions are observable: which units share a slice,
 * which take a fresh one, and in what order.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, type ProbeResult } from '@device-id/collector/canonical';
import { collectForIdentity, measureDeferred } from '@device-id/collector/index';
import {
    FALLBACK_SLICE_MS,
    FONT_METRICS_STEPS,
    MIN_SLICE_REMAINING_MS,
    SCRIPTS_STEPS,
    TIER,
    VALUE_PROBES,
    enabledProbesOf,
    fontsReady,
    nextIdle,
    runDeferred,
    type UnitTrace,
} from '@device-id/collector/value-probes';

/** Install a `requestIdleCallback` whose deadline reports `remaining()` and runs the callback on a macrotask. */
function installIdle(remaining: () => number): { undo: () => void; calls: () => number } {
    let calls = 0;
    vi.stubGlobal('requestIdleCallback', (callback: (deadline: IdleDeadline) => void) => {
        calls++;
        setTimeout(() => callback({ didTimeout: false, timeRemaining: remaining } as IdleDeadline), 0);
        return calls;
    });

    return { undo: () => vi.unstubAllGlobals(), calls: () => calls };
}

/**
 * A fake 2D context (jsdom has none): `measureText` widths are a function of the font
 * string, so `fontMetricsSteps()` can run and its steps can be traced.
 */
function installFakeCanvas(): () => void {
    const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
    const original = proto.getContext;
    proto.getContext = function fakeGetContext(kind: string): unknown {
        if (kind !== '2d') return null;
        return {
            font: '',
            measureText(text: string) {
                const width = (this.font.includes('"Arial"') ? 100 : 50) + text.length;
                return { width, actualBoundingBoxAscent: width / 2, actualBoundingBoxDescent: 0, actualBoundingBoxLeft: 0, actualBoundingBoxRight: width };
            },
        };
    };

    return () => {
        proto.getContext = original;
    };
}

afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
});

describe('nextIdle', () => {
    it('hands out the engine’s IdleDeadline where requestIdleCallback exists', async () => {
        installIdle(() => 42);
        expect((await nextIdle()).timeRemaining()).toBe(42);
    });

    it('hands out a 16 ms budget counted from the slice start where it does not', async () => {
        const budget = await nextIdle();
        const first = budget.timeRemaining();
        expect(first).toBeGreaterThan(0);
        expect(first).toBeLessThanOrEqual(FALLBACK_SLICE_MS);
        const until = Date.now() + FALLBACK_SLICE_MS + 5;
        while (Date.now() < until) { /* spend the budget */ }
        expect(budget.timeRemaining()).toBe(0);
    });
});

describe('fontsReady', () => {
    it('resolves at once without document.fonts', async () => {
        const started = Date.now();
        await fontsReady(300);
        expect(Date.now() - started).toBeLessThan(100);
    });

    it('is bounded when fonts.ready never settles', async () => {
        Object.defineProperty(document, 'fonts', { value: { ready: new Promise(() => undefined) }, configurable: true });
        try {
            const started = Date.now();
            await fontsReady(30);
            expect(Date.now() - started).toBeGreaterThanOrEqual(25);
            expect(Date.now() - started).toBeLessThan(1000);
        } finally {
            delete (document as unknown as Record<string, unknown>).fonts;
        }
    });
});

describe('runDeferred', () => {
    const traceOf = async (remaining: () => number, tiers = [TIER.TWO, TIER.HARDWARE] as const, disabled: string[] = []): Promise<UnitTrace[]> => {
        installIdle(remaining);
        const units: UnitTrace[] = [];
        await runDeferred(tiers, { disabled, trace: (unit) => units.push(unit) });
        return units;
    };

    it('runs the late probes (audio, behaviour) of BOTH tiers after every other probe', async () => {
        const units = await traceOf(() => 50);
        const names = units.map((u) => u.name);
        const late = VALUE_PROBES.filter((p) => p.late).map((p) => p.name);
        expect(late).toEqual(['audioRealtime', 'audioOffline', 'audioHardware', 'behavior']);
        const firstLate = Math.min(...late.map((name) => names.indexOf(name)));
        for (const [index, name] of names.entries()) {
            if (late.includes(name)) continue;
            expect(index, `${name} must precede the audio probes`).toBeLessThan(firstLate);
        }
    });

    it('spreads fontMetrics over FONT_METRICS_STEPS units and puts every heavy unit in a fresh slice', async () => {
        const undo = installFakeCanvas();
        try {
            const units = await traceOf(() => 50);
            const fontUnits = units.filter((u) => u.name === 'fontMetrics');
            expect(fontUnits.map((u) => u.step)).toEqual(Array.from({ length: FONT_METRICS_STEPS }, (_, i) => `${i + 1}/${FONT_METRICS_STEPS}`));
            // One slice per step: each chunk is a unit of a heavy probe.
            expect(new Set(fontUnits.map((u) => u.slice)).size).toBe(FONT_METRICS_STEPS);

            const heavy = new Set(VALUE_PROBES.filter((p) => p.heavy).map((p) => p.name));
            for (const [index, unit] of units.entries()) {
                if (!heavy.has(unit.name)) continue;
                const previous = units[index - 1];
                if (previous) expect(unit.slice, `${unit.name} ${unit.step ?? ''} must not share slice ${previous.slice} with ${previous.name}`).toBeGreaterThan(previous.slice);
            }
        } finally {
            undo();
        }
    });

    it('starts the next unit in the same slice only while the deadline has MIN_SLICE_REMAINING_MS, else takes a fresh one', async () => {
        // A deadline that is exhausted: every unit needs its own slice.
        const exhausted = await traceOf(() => MIN_SLICE_REMAINING_MS - 1);
        expect(new Set(exhausted.map((u) => u.slice)).size).toBe(exhausted.length);

        // A generous deadline: the cheap, non-heavy neighbours share slices.
        const generous = await traceOf(() => 1000);
        expect(new Set(generous.map((u) => u.slice)).size).toBeLessThan(generous.length);
        for (const unit of generous) expect(unit.remainingMs).toBe(1000);
    });

    it('returns every enabled probe of the tiers as a tagged result and honours the policy', async () => {
        installIdle(() => 50);
        const out = await runDeferred([TIER.TWO, TIER.HARDWARE], { disabled: ['voices', 'workerScope'] });
        const expected = [...enabledProbesOf(TIER.TWO, ['voices', 'workerScope']), ...enabledProbesOf(TIER.HARDWARE, ['voices', 'workerScope'])].map((p) => p.name).sort();
        expect(Object.keys(out).sort()).toEqual(expected);
        expect(out).not.toHaveProperty('voices');
        for (const value of Object.values(out)) expect(['ok', 'unavailable', 'error']).toContain(value.state);
    });

    it('stops starting units once aborted and leaves what settled in `out`', async () => {
        installIdle(() => 50);
        const out: Record<string, ProbeResult<unknown>> = {};
        let started = 0;
        const aborted = (): boolean => started++ >= 3;
        await runDeferred([TIER.TWO], { out, aborted });
        expect(Object.keys(out).length).toBeGreaterThanOrEqual(1);
        expect(Object.keys(out).length).toBeLessThan(enabledProbesOf(TIER.TWO).length);
    });

    it('waits for document.fonts.ready (bounded) once, before the first font-dependent unit', async () => {
        installIdle(() => 50);
        const undoCanvas = installFakeCanvas();
        let resolveFonts: (() => void) | undefined;
        const ready = new Promise<void>((resolve) => {
            resolveFonts = resolve;
        });
        Object.defineProperty(document, 'fonts', { value: { ready }, configurable: true });
        try {
            const units: UnitTrace[] = [];
            const run = runDeferred([TIER.HARDWARE], { trace: (unit) => units.push(unit) });
            // Nothing font-dependent may start while fonts.ready is pending (fontMetrics is first).
            await new Promise((r) => setTimeout(r, 30));
            expect(units.map((u) => u.name)).not.toContain('fontMetrics');
            resolveFonts?.();
            await run;
            expect(units.map((u) => u.name)).toContain('fontMetrics');
        } finally {
            delete (document as unknown as Record<string, unknown>).fonts;
            undoCanvas();
        }
    });

    it('spreads scripts over SCRIPTS_STEPS units, each in a fresh slice (round-3 CL3-5)', async () => {
        const undo = installFakeCanvas();
        try {
            const units = await traceOf(() => 50);
            const scriptUnits = units.filter((u) => u.name === 'scripts');
            expect(scriptUnits.map((u) => u.step)).toEqual(Array.from({ length: SCRIPTS_STEPS }, (_, i) => `${i + 1}/${SCRIPTS_STEPS}`));
            expect(new Set(scriptUnits.map((u) => u.slice)).size).toBe(SCRIPTS_STEPS);
        } finally {
            undo();
        }
    });

    it('audioReadback and emojiMetrics open their own slices (round-3 CL3-5)', async () => {
        const undo = installFakeCanvas();
        try {
            const units = await traceOf(() => 50);
            for (const [name, previous] of [['audioReadback', 'timezoneLmt'], ['emojiMetrics', 'fontMetrics']] as const) {
                const unit = units.find((u) => u.name === name);
                const before = units.filter((u) => u.name === previous).at(-1);
                expect(unit && before, name).toBeTruthy();
                expect((unit as UnitTrace).slice, `${name} after ${previous}`).toBeGreaterThan((before as UnitTrace).slice);
            }
        } finally {
            undo();
        }
    });

    describe('abort (round-3 CL3-3)', () => {
        it('stops between the steps of a stepped probe and leaves the cut probe out', async () => {
            const undo = installFakeCanvas();
            try {
                installIdle(() => 50);
                const units: UnitTrace[] = [];
                const out: Record<string, ProbeResult<unknown>> = {};
                await runDeferred([TIER.HARDWARE], {
                    out,
                    trace: (unit) => units.push(unit),
                    aborted: () => units.some((u) => u.name === 'fontMetrics'),
                });
                expect(units.filter((u) => u.name === 'fontMetrics')).toHaveLength(1);
                expect(units).toHaveLength(1);
                // Half the families would be a different value, not a partial one.
                expect(out).not.toHaveProperty('fontMetrics');
                expect(Object.keys(out)).toHaveLength(0);
            } finally {
                undo();
            }
        });

        it('does not start a unit whose idle slice arrives after the abort', async () => {
            let abort = false;
            let slices = 0;
            vi.stubGlobal('requestIdleCallback', (callback: (deadline: IdleDeadline) => void) => {
                slices++;
                setTimeout(() => {
                    // The caller gives up while the scheduler waits for its second slice.
                    if (slices === 2) abort = true;
                    callback({ didTimeout: false, timeRemaining: () => 0 } as IdleDeadline);
                }, 0);
                return slices;
            });
            const units: UnitTrace[] = [];
            const out: Record<string, ProbeResult<unknown>> = {};
            await runDeferred([TIER.TWO], { out, trace: (unit) => units.push(unit), aborted: () => abort });

            expect(units).toHaveLength(1);
            expect(Object.keys(out)).toEqual([units[0]?.name]);
            expect(slices).toBe(2);
        });

        it('does not start a font-dependent unit when the abort came during the fonts wait', async () => {
            const undoCanvas = installFakeCanvas();
            installIdle(() => 50);
            let resolveFonts: (() => void) | undefined;
            Object.defineProperty(document, 'fonts', { value: { ready: new Promise<void>((resolve) => { resolveFonts = resolve; }) }, configurable: true });
            try {
                let abort = false;
                const units: UnitTrace[] = [];
                const run = runDeferred([TIER.HARDWARE], { trace: (unit) => units.push(unit), aborted: () => abort });
                await new Promise((r) => setTimeout(r, 10));
                abort = true;
                resolveFonts?.();
                await run;
                expect(units).toHaveLength(0);
            } finally {
                delete (document as unknown as Record<string, unknown>).fonts;
                undoCanvas();
            }
        });
    });

    it('a stepped probe whose step throws is `error`, not a rejection', async () => {
        installIdle(() => 50);
        const out = await runDeferred([TIER.HARDWARE]);
        // jsdom has no 2D context: fontMetricsSteps() throws, and the probe is tagged.
        expect(out.fontMetrics).toEqual(expect.objectContaining({ state: 'error' }));
        expect(ok(1)).toEqual({ state: 'ok', value: 1 });
    });
});

describe('measureDeferred and collectForIdentity on the schedule', () => {
    it('measureDeferred traces the deferred integrity phase in slice 0 and the probes after it', async () => {
        installIdle(() => 50);
        const units = await measureDeferred();
        expect(units[0]?.name).toBe('integrityDeferred');
        expect(units[0]?.slice).toBe(0);
        expect(units.slice(1).every((u) => u.slice >= 1)).toBe(true);
        expect(units.map((u) => u.name)).toContain('audioHardware');
    });

    it('collectForIdentity sends what settled when the cap passes mid-schedule (decision D5)', async () => {
        // The first slices arrive at once; every later slice never arrives, so the
        // schedule can only end through the cap, with exactly the probes of the
        // delivered slices settled. Deterministic under any machine load: the
        // previous 15 ms slices against a 120 ms wall-clock cap let a loaded run
        // settle none (or all) before the cap.
        const deliveredSlices = 3;
        let slices = 0;
        vi.stubGlobal('requestIdleCallback', (callback: (deadline: IdleDeadline) => void) => {
            slices += 1;
            if (slices <= deliveredSlices) {
                setTimeout(() => callback({ didTimeout: false, timeRemaining: () => 0 } as IdleDeadline), 0);
            }
            return slices;
        });
        const claims = await collectForIdentity(2_000, []);
        const deferredNames = [...enabledProbesOf(TIER.TWO), ...enabledProbesOf(TIER.HARDWARE)].map((p) => p.name);
        const settled = Object.keys(claims.tier2 ?? {});
        expect(settled.length).toBeGreaterThan(0);
        expect(settled.length).toBeLessThan(deferredNames.length);
        expect(claims.timing.tier2Skipped).toBe(false);
        for (const name of settled) expect(deferredNames).toContain(name);
    });
});

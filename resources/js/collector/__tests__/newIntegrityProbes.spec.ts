/**
 * `canvasPattern` and `automationMarks` (integrity, probe set 4), and their findings
 * `canvas_pattern_perturbed`, `automation_global_present`, `headless_shell_geometry`.
 *
 * jsdom has no 2D context, so the canvas tests install a fake that really stores and returns
 * pixels. Each finding is shown to FIRE on the tampering it targets and to stay silent on a
 * conformant environment.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { automationMarks, canvasPattern, collectIntegrity, INTEGRITY_CODES } from '@device-id/collector/integrity';

const undos: Array<() => void> = [];
afterEach(() => {
    while (undos.length) undos.pop()?.();
});

function defineOwn(target: object, name: string, value: unknown): void {
    const original = Object.getOwnPropertyDescriptor(target, name);
    Object.defineProperty(target, name, { configurable: true, writable: true, enumerable: true, value });
    undos.push(() => {
        if (original) Object.defineProperty(target, name, original);
        else delete (target as Record<string, unknown>)[name];
    });
}

type ReadBack = (data: Uint8ClampedArray, readIndex: number) => Uint8ClampedArray;

function installPixelCanvas(readBack: ReadBack = (data) => data): void {
    const proto = HTMLCanvasElement.prototype as unknown as { getContext: unknown };
    const original = proto.getContext;
    let reads = 0;
    proto.getContext = function fakeGetContext(this: HTMLCanvasElement, kind: string): unknown {
        if (kind !== '2d') return null;
        const width = this.width;
        const pixels = new Uint8ClampedArray(width * this.height * 4);
        return {
            fillStyle: '#000000',
            fillRect(x: number, y: number, w: number, h: number) {
                const m = /^rgb\((\d+),(\d+),(\d+)\)$/.exec(String(this.fillStyle)) as RegExpExecArray;
                for (let row = y; row < y + h; row++) {
                    for (let col = x; col < x + w; col++) pixels.set([Number(m[1]), Number(m[2]), Number(m[3]), 255], (row * width + col) * 4);
                }
            },
            getImageData(x: number, y: number, w: number, h: number) {
                const out = new Uint8ClampedArray(w * h * 4);
                for (let row = 0; row < h; row++) {
                    const from = ((y + row) * width + x) * 4;
                    out.set(pixels.subarray(from, from + w * 4), row * w * 4);
                }
                return { data: readBack(out, reads++), width: w, height: h };
            },
        };
    };
    undos.push(() => {
        proto.getContext = original;
    });
}

/** The pixel at (x, y) of a 64×64 RGBA buffer. */
const at = (x: number, y: number): number => (y * 64 + x) * 4;

describe('canvasPattern', () => {
    it('is exact and stable on a conformant canvas', () => {
        installPixelCanvas();
        expect(canvasPattern()).toEqual({ state: 'ok', value: { exact: true, deviations: 0, stable: true } });
    });

    it('catches noise that leaves a uniform region alone: one flipped low bit on an EDGE pixel', () => {
        // Firefox and WebKit skip uniform images, so canvasFill passes; the pattern has edges.
        installPixelCanvas((data) => {
            const noisy = data.slice();
            noisy[at(8, 0)] = (noisy[at(8, 0)] as number) ^ 1;
            return noisy;
        });
        const result = canvasPattern();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.exact).toBe(false);
        expect(result.value.deviations).toBe(1);
        expect(result.value.stable).toBe(true);
    });

    it('reports a per-read randomisation as unstable', () => {
        installPixelCanvas((data, index) => {
            const noisy = data.slice();
            noisy[at(3, 3)] = index === 0 ? 11 : 12;
            return noisy;
        });
        const result = canvasPattern();
        expect(result.state === 'ok' && result.value.stable).toBe(false);
    });

    it('counts a short read as deviations and has no verdict without a 2D context', () => {
        installPixelCanvas((data) => data.subarray(0, data.length - 16));
        const short = canvasPattern();
        expect(short.state === 'ok' && short.value.deviations).toBe(4);

        // jsdom without the fake: getContext is not implemented and returns null.
        undos.pop()?.();
        expect(canvasPattern()).toEqual({ state: 'unavailable', reason: 'no-2d-context' });
    });

    it('raises canvas_pattern_perturbed in collectIntegrity only when the pattern deviates', () => {
        installPixelCanvas();
        expect(collectIntegrity().findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.CANVAS_PATTERN_PERTURBED);
        undos.pop()?.();

        installPixelCanvas((data) => {
            const noisy = data.slice();
            noisy[at(8, 0)] = 0;
            return noisy;
        });
        expect(collectIntegrity().findings.map((f) => f.code)).toContain(INTEGRITY_CODES.CANVAS_PATTERN_PERTURBED);
    });

    it('is skipped, and raises nothing, when the policy names it', () => {
        installPixelCanvas((data) => data.fill(0));
        const report = collectIntegrity(['canvasPattern']);
        expect(report.data).not.toHaveProperty('canvasPattern');
        expect(report.findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.CANVAS_PATTERN_PERTURBED);
    });
});

describe('automationMarks', () => {
    it('finds nothing on a clean window', () => {
        const result = automationMarks();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value.globals).toBe(0);
        expect(result.value.cdc).toBe(false);
        expect(result.value.pw).toBe(false);
        expect(collectIntegrity().findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.AUTOMATION_GLOBAL_PRESENT);
    });

    it('counts a ChromeDriver document property and a Playwright window binding, and never reports their names', () => {
        defineOwn(document, '$cdc_asdjflasutopfhvcZLmcfl_', {});
        defineOwn(window, '__playwright__binding__', () => undefined);
        const result = automationMarks();
        expect(result.state).toBe('ok');
        if (result.state !== 'ok') return;
        expect(result.value).toMatchObject({ globals: 2, cdc: true, pw: true });
        expect(JSON.stringify(result)).not.toMatch(/cdc_asdj|playwright/);
        expect(collectIntegrity().findings.map((f) => f.code)).toContain(INTEGRITY_CODES.AUTOMATION_GLOBAL_PRESENT);
    });

    it('recognises the other driver families', () => {
        for (const name of ['__pwInitScripts', 'callPhantom', '_phantom', 'domAutomationController', '_Selenium_IDE_Recorder', '__fxdriver_unwrapped', '__driver_unwrapped', '$chrome_asyncScriptInfo']) {
            defineOwn(window, name, 1);
            const result = automationMarks();
            expect(result.state === 'ok' && result.value.globals, name).toBe(1);
            undos.pop()?.();
        }
    });

    it('does not score a global that domBlockers already reports', () => {
        defineOwn(window, '__webdriver_evaluate', () => undefined);
        const result = automationMarks();
        expect(result.state === 'ok' && result.value.globals).toBe(0);
    });

    it('ignores honest globals that merely look similar', () => {
        for (const name of ['__pwa_install', 'driverName', 'webdriverHelper', 'phantomLimb', 'playwrightLike']) defineOwn(window, name, 1);
        const result = automationMarks();
        expect(result.state === 'ok' && result.value.globals).toBe(0);
    });

    it('reports outer = inner on a desktop browser window only, and raises headless_shell_geometry with history length 1', () => {
        const media = (browser: boolean, coarse: boolean) => (query: string) => ({ matches: query.includes('display-mode') ? browser : query.includes('pointer: coarse') ? coarse : false });
        defineOwn(window, 'matchMedia', vi.fn(media(true, false)));
        defineOwn(window, 'innerWidth', 1280);
        defineOwn(window, 'innerHeight', 720);
        defineOwn(window, 'outerWidth', 1280);
        defineOwn(window, 'outerHeight', 720);

        const headless = automationMarks();
        expect(headless.state === 'ok' && headless.value.outerEqualsInner).toBe(true);
        expect(history.length).toBe(1);
        expect(collectIntegrity().findings.map((f) => f.code)).toContain(INTEGRITY_CODES.HEADLESS_SHELL_GEOMETRY);

        // A windowed browser has chrome around the viewport.
        defineOwn(window, 'outerHeight', 820);
        const windowed = automationMarks();
        expect(windowed.state === 'ok' && windowed.value.outerEqualsInner).toBe(false);
        expect(collectIntegrity().findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.HEADLESS_SHELL_GEOMETRY);

        // A touch-first device or an installed app is not a desktop browser window.
        defineOwn(window, 'outerHeight', 720);
        defineOwn(window, 'matchMedia', vi.fn(media(true, true)));
        expect(automationMarks().state === 'ok' && (automationMarks() as { value: { outerEqualsInner: unknown } }).value.outerEqualsInner).toBeNull();
        defineOwn(window, 'matchMedia', vi.fn(media(false, false)));
        expect((automationMarks() as { value: { outerEqualsInner: unknown } }).value.outerEqualsInner).toBeNull();
    });

    it('has no geometry verdict where matchMedia is missing, and is skipped by the policy', () => {
        defineOwn(window, '__playwright__binding__', 1);
        const report = collectIntegrity(['automationMarks']);
        expect(report.data).not.toHaveProperty('automationMarks');
        expect(report.findings.map((f) => f.code)).not.toContain(INTEGRITY_CODES.AUTOMATION_GLOBAL_PRESENT);
    });
});

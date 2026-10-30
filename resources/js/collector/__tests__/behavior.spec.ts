/**
 * Passive behavioural aggregates (behavior.ts): session data, never device identity.
 *
 * The listeners are real (jsdom dispatches real events); what is asserted is what reaches the
 * snapshot, what is deliberately NOT in it, and that the listeners go away again.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { fnv1a32 } from '@device-id/collector/canonical';
import {
    behavior,
    hasBehaviorData,
    isBehaviorCollecting,
    resetBehaviorForTests,
    startBehaviorCollection,
    stopBehaviorCollection,
} from '@device-id/collector/behavior';

function snapshotValue(): Record<string, any> {
    const result = behavior();
    if (result.state !== 'ok') {
        throw new Error(`expected an ok snapshot, got ${result.state}`);
    }

    return result.value as Record<string, any>;
}

const move = (x: number, y: number): void => {
    window.dispatchEvent(new MouseEvent('pointermove', { clientX: x, clientY: y }));
};

describe('behavior', () => {
    beforeEach(() => resetBehaviorForTests());
    afterEach(() => resetBehaviorForTests());

    it('is unavailable("not-started") on a page that never started collection', () => {
        expect(behavior()).toEqual({ state: 'unavailable', reason: 'not-started' });
        // Events before start are not recorded either.
        move(1, 1);
        startBehaviorCollection();
        expect(behavior()).toEqual({ state: 'unavailable', reason: 'no-interaction' });
    });

    it('is unavailable("no-interaction") until real input arrives; focus and visibility are not input', () => {
        startBehaviorCollection();
        window.dispatchEvent(new Event('focus'));
        document.dispatchEvent(new Event('visibilitychange'));

        expect(hasBehaviorData()).toBe(false);
        expect(behavior()).toEqual({ state: 'unavailable', reason: 'no-interaction' });
    });

    it('counts pointer moves and measures the path length, not the coordinates', () => {
        startBehaviorCollection();
        move(1000, 2000);
        move(1003, 2004);

        const value = snapshotValue();
        expect(value.pointer.moves).toBe(2);
        expect(value.pointer.path).toBe(5);
        expect(JSON.stringify(value)).not.toMatch(/1000|1003|2000|2004/);
    });

    it('records the physical key codes only as a count and a hash, never the codes or the typed key', () => {
        startBehaviorCollection();
        for (const [code, key] of [['KeyQ', 'q'], ['KeyZ', 'z'], ['Digit7', '7']] as const) {
            window.dispatchEvent(new KeyboardEvent('keydown', { code, key }));
            window.dispatchEvent(new KeyboardEvent('keyup', { code, key }));
        }

        const value = snapshotValue();
        expect(value.keyboard.down).toBe(3);
        expect(value.keyboard.up).toBe(3);
        expect(value.keyboard.codeCount).toBe(3);
        expect(value.keyboard.codesHash).toBe(fnv1a32(['Digit7', 'KeyQ', 'KeyZ'].join('|')));
        expect(JSON.stringify(value)).not.toMatch(/KeyQ|KeyZ|Digit7/);
    });

    it('caps the distinct key codes it remembers', () => {
        startBehaviorCollection();
        for (let i = 0; i < 80; i++) {
            window.dispatchEvent(new KeyboardEvent('keydown', { code: `Code${i}` }));
        }

        expect(snapshotValue().keyboard.codeCount).toBe(32);
    });

    it('counts wheel and touch input', () => {
        startBehaviorCollection();
        window.dispatchEvent(new WheelEvent('wheel', { deltaY: 40 }));
        window.dispatchEvent(new WheelEvent('wheel', { deltaY: -40 }));
        window.dispatchEvent(new Event('touchstart'));

        const value = snapshotValue();
        expect(value.wheel.count).toBe(2);
        expect(value.wheel.deltaAbs.mean).toBe(40);
        expect(value.touch.starts).toBe(1);
    });

    it('installs its listeners once: a second start does not double-count', () => {
        startBehaviorCollection();
        startBehaviorCollection();
        window.dispatchEvent(new MouseEvent('pointerdown'));

        expect(snapshotValue().pointer.downs).toBe(1);
    });

    it('stop removes every listener, keeps the aggregates readable, and a restart records again', () => {
        startBehaviorCollection();
        expect(isBehaviorCollecting()).toBe(true);
        window.dispatchEvent(new MouseEvent('pointerdown'));

        stopBehaviorCollection();
        expect(isBehaviorCollecting()).toBe(false);
        window.dispatchEvent(new MouseEvent('pointerdown'));
        window.dispatchEvent(new KeyboardEvent('keydown', { code: 'KeyA' }));

        const stopped = snapshotValue();
        expect(stopped.pointer.downs).toBe(1);
        expect(stopped.keyboard.down).toBe(0);

        startBehaviorCollection();
        window.dispatchEvent(new MouseEvent('pointerdown'));
        expect(snapshotValue().pointer.downs).toBe(2);
    });

    it('never lets a handler failure reach the page (window error event)', () => {
        const errors: unknown[] = [];
        const onError = (event: ErrorEvent): void => {
            errors.push(event.error);
        };
        window.addEventListener('error', onError);
        try {
            startBehaviorCollection();
            const hostile = new MouseEvent('pointermove', { clientX: 1, clientY: 1 });
            Object.defineProperty(hostile, 'getCoalescedEvents', {
                value: () => {
                    throw new Error('hostile coalesced events');
                },
            });
            window.dispatchEvent(hostile);
            move(2, 2);
        } finally {
            window.removeEventListener('error', onError);
        }

        expect(errors).toEqual([]);
        expect(snapshotValue().pointer.moves).toBeGreaterThanOrEqual(1);
    });

    it('reports a snapshot whose numbers are all finite (no Infinity from empty statistics)', () => {
        startBehaviorCollection();
        window.dispatchEvent(new MouseEvent('pointerdown'));

        const json = JSON.stringify(snapshotValue());
        expect(json).not.toMatch(/null|Infinity|NaN/);
    });
});

describe('behavior payload size', () => {
    beforeEach(() => resetBehaviorForTests());
    afterEach(() => resetBehaviorForTests());

    it('stays inside the body budget when every statistic is populated (measured 1 879 B in Chromium)', () => {
        startBehaviorCollection();
        for (let i = 0; i < 400; i++) {
            window.dispatchEvent(new MouseEvent('pointermove', { clientX: i * 3, clientY: i * 2 }));
            window.dispatchEvent(new KeyboardEvent('keydown', { code: `Key${String.fromCharCode(65 + (i % 26))}`, location: i % 4 }));
            window.dispatchEvent(new KeyboardEvent('keyup', { code: `Key${String.fromCharCode(65 + (i % 26))}` }));
            window.dispatchEvent(new WheelEvent('wheel', { deltaY: i * 1.37, deltaX: i * 0.11, deltaMode: i % 3 }));
        }

        const bytes = new TextEncoder().encode(JSON.stringify(snapshotValue())).byteLength;
        // The transport ceiling is 24 KiB for a whole envelope; the whole behaviour block must
        // stay a small fraction of it, whatever the visitor did.
        expect(bytes).toBeLessThan(3000);
    });
});

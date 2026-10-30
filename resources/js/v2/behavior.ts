/**
 * Passive behavioural signals, collected for device fingerprinting only.
 *
 * This module is NOT a biometric authenticator and it is not a feature. It exists because
 * the input stack is part of the device: pointer polling rate, coalesced-event behaviour,
 * pressure/contact geometry, keyboard layout, wheel deltas and motion-sensor noise are
 * properties a page can observe without asking the visitor to do anything. Those are the
 * values this module records; it does not record what was typed, where the pointer went, or
 * any raw coordinates.
 *
 * ## What is deliberately not stored
 *
 * - No `KeyboardEvent.key`, `charCode` or `keyCode`: only the physical `code` is hashed,
 *   and the full set never leaves the browser.
 * - No pointer coordinates beyond the running path length and speed aggregates.
 * - No raw touch points, no raw sensor samples, no timestamps.
 * - No DOM mutation and no console output. Listeners are passive and capture-phase so they
 *   cannot change the page's behaviour.
 *
 * Aggregates only, capped sets only. The snapshot is therefore safe to send as a tier-2
 * claim and small enough for the keepalive budget.
 */

import { fnv1a32, ok, unavailable, type ProbeResult } from './canonical';

const MAX_DISTINCT = 16;
const MAX_TYPES = 8;
const MAX_CODES = 32;
const MAX_LOCATIONS = 8;
const MAX_MODES = 4;
const MAX_TOUCHES_PER_EVENT = 10;

interface Stats {
    count: number;
    sum: number;
    sumSquares: number;
    min: number;
    max: number;
    distinct: Set<string>;
}

const emptyStats = (): Stats => ({
    count: 0,
    sum: 0,
    sumSquares: 0,
    min: Number.POSITIVE_INFINITY,
    max: Number.NEGATIVE_INFINITY,
    distinct: new Set<string>(),
});

const add = (stats: Stats, value: number, distinctKey?: string): void => {
    if (!Number.isFinite(value)) {
        return;
    }

    stats.count += 1;
    stats.sum += value;
    stats.sumSquares += value * value;
    stats.min = Math.min(stats.min, value);
    stats.max = Math.max(stats.max, value);

    if (distinctKey !== undefined && stats.distinct.size < MAX_DISTINCT) {
        stats.distinct.add(distinctKey);
    }
};

const remember = (set: Set<string>, value: string, cap: number): void => {
    if (value !== '' && set.size < cap) {
        set.add(value);
    }
};

const round = (value: number): number => Math.round(value * 1000) / 1000;

const snapshotStats = (stats: Stats): Record<string, number> => {
    if (stats.count === 0) {
        return { count: 0 };
    }

    const mean = stats.sum / stats.count;
    const variance = Math.max(0, stats.sumSquares / stats.count - mean * mean);

    return {
        count: stats.count,
        mean: round(mean),
        min: round(stats.min),
        max: round(stats.max),
        stddev: round(Math.sqrt(variance)),
        distinct: stats.distinct.size,
    };
};

const state = {
    started: false,
    startedAt: 0,
    pointer: {
        moves: 0,
        downs: 0,
        ups: 0,
        cancels: 0,
        raw: 0,
        types: new Set<string>(),
        coalesced: emptyStats(),
        coalescedMax: 0,
        pressure: emptyStats(),
        width: emptyStats(),
        height: emptyStats(),
        tiltX: emptyStats(),
        tiltY: emptyStats(),
        twist: emptyStats(),
        path: 0,
        speed: emptyStats(),
        lastX: 0,
        lastY: 0,
        lastAt: 0,
    },
    touch: {
        starts: 0,
        moves: 0,
        ends: 0,
        force: emptyStats(),
        radiusX: emptyStats(),
        radiusY: emptyStats(),
        altitude: emptyStats(),
        azimuth: emptyStats(),
        interval: emptyStats(),
        lastAt: 0,
    },
    keyboard: {
        down: 0,
        up: 0,
        repeat: 0,
        codes: new Set<string>(),
        locations: new Set<string>(),
        dwell: emptyStats(),
        flight: emptyStats(),
        downAt: new Map<string, number>(),
        lastDownAt: 0,
    },
    wheel: {
        count: 0,
        modes: new Set<string>(),
        deltaAbs: emptyStats(),
        deltaY: emptyStats(),
        deltaX: emptyStats(),
    },
    motion: {
        events: 0,
        intervals: emptyStats(),
        accel: emptyStats(),
        orientation: 0,
        lastAt: 0,
    },
    events: {
        copy: 0,
        cut: 0,
        paste: 0,
        selection: 0,
        scroll: 0,
        focus: 0,
        blur: 0,
        visibility: 0,
    },
};

const now = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());

const listen = (target: Window | Document, type: string, handler: EventListener): void => {
    try {
        target.addEventListener(type, handler, { passive: true, capture: true });
    } catch {
        // A target that rejects the listener is a target this module cannot observe.
    }
};

const onPointer = (event: Event): void => {
    const pointer = event as PointerEvent;
    const time = typeof pointer.timeStamp === 'number' && pointer.timeStamp > 0 ? pointer.timeStamp : now();

    if (typeof pointer.pointerType === 'string') {
        remember(state.pointer.types, pointer.pointerType, MAX_TYPES);
    }

    if (pointer.type === 'pointermove') {
        state.pointer.moves += 1;

        const coalesced = typeof pointer.getCoalescedEvents === 'function'
            ? pointer.getCoalescedEvents().length
            : 0;
        add(state.pointer.coalesced, coalesced);
        state.pointer.coalescedMax = Math.max(state.pointer.coalescedMax, coalesced);

        add(state.pointer.pressure, pointer.pressure, String(round(pointer.pressure)));
        add(state.pointer.width, pointer.width, String(round(pointer.width)));
        add(state.pointer.height, pointer.height, String(round(pointer.height)));
        add(state.pointer.tiltX, pointer.tiltX);
        add(state.pointer.tiltY, pointer.tiltY);
        add(state.pointer.twist, pointer.twist);

        if (state.pointer.lastAt > 0) {
            const dx = pointer.clientX - state.pointer.lastX;
            const dy = pointer.clientY - state.pointer.lastY;
            const distance = Math.hypot(dx, dy);
            const elapsed = time - state.pointer.lastAt;

            state.pointer.path += distance;
            if (elapsed > 0) {
                add(state.pointer.speed, (distance / elapsed) * 1000);
            }
        }

        state.pointer.lastX = pointer.clientX;
        state.pointer.lastY = pointer.clientY;
        state.pointer.lastAt = time;

        return;
    }

    if (pointer.type === 'pointerdown') {
        state.pointer.downs += 1;
    } else if (pointer.type === 'pointerup') {
        state.pointer.ups += 1;
    } else if (pointer.type === 'pointercancel') {
        state.pointer.cancels += 1;
    }

    state.pointer.lastX = pointer.clientX;
    state.pointer.lastY = pointer.clientY;
    state.pointer.lastAt = time;
};

const onPointerRaw = (): void => {
    state.pointer.raw += 1;
};

const onTouch = (event: Event): void => {
    const touch = event as TouchEvent;
    const time = typeof touch.timeStamp === 'number' && touch.timeStamp > 0 ? touch.timeStamp : now();

    if (touch.type === 'touchstart') {
        state.touch.starts += 1;
    } else if (touch.type === 'touchmove') {
        state.touch.moves += 1;
    } else if (touch.type === 'touchend') {
        state.touch.ends += 1;
    }

    if (state.touch.lastAt > 0) {
        add(state.touch.interval, time - state.touch.lastAt);
    }
    state.touch.lastAt = time;

    const touches = Array.from(touch.changedTouches ?? []).slice(0, MAX_TOUCHES_PER_EVENT);
    for (const point of touches) {
        const extended = point as Touch & { altitudeAngle?: number; azimuthAngle?: number };

        add(state.touch.force, point.force, String(round(point.force)));
        add(state.touch.radiusX, point.radiusX, String(round(point.radiusX)));
        add(state.touch.radiusY, point.radiusY, String(round(point.radiusY)));

        if (typeof extended.altitudeAngle === 'number') {
            add(state.touch.altitude, extended.altitudeAngle);
        }
        if (typeof extended.azimuthAngle === 'number') {
            add(state.touch.azimuth, extended.azimuthAngle);
        }
    }
};

const onKey = (event: Event): void => {
    const key = event as KeyboardEvent;
    const time = typeof key.timeStamp === 'number' && key.timeStamp > 0 ? key.timeStamp : now();
    const code = typeof key.code === 'string' && key.code !== '' ? key.code : 'unknown';

    if (key.type === 'keydown') {
        state.keyboard.down += 1;

        if (key.repeat) {
            state.keyboard.repeat += 1;
        } else {
            if (state.keyboard.lastDownAt > 0) {
                add(state.keyboard.flight, time - state.keyboard.lastDownAt);
            }
            state.keyboard.lastDownAt = time;
        }

        remember(state.keyboard.codes, code, MAX_CODES);
        remember(state.keyboard.locations, String(key.location), MAX_LOCATIONS);

        if (!key.repeat && state.keyboard.downAt.size < MAX_CODES) {
            state.keyboard.downAt.set(code, time);
        }

        return;
    }

    if (key.type === 'keyup') {
        state.keyboard.up += 1;
        const downAt = state.keyboard.downAt.get(code);

        if (downAt !== undefined) {
            add(state.keyboard.dwell, time - downAt);
            state.keyboard.downAt.delete(code);
        }
    }
};

const onWheel = (event: Event): void => {
    const wheel = event as WheelEvent;

    state.wheel.count += 1;
    remember(state.wheel.modes, String(wheel.deltaMode), MAX_MODES);
    add(state.wheel.deltaAbs, Math.abs(wheel.deltaY));
    add(state.wheel.deltaY, wheel.deltaY);
    add(state.wheel.deltaX, wheel.deltaX);
};

const onMotion = (event: Event): void => {
    const motion = event as DeviceMotionEvent;
    const time = typeof motion.timeStamp === 'number' && motion.timeStamp > 0 ? motion.timeStamp : now();

    state.motion.events += 1;
    if (state.motion.lastAt > 0) {
        add(state.motion.intervals, time - state.motion.lastAt);
    }
    state.motion.lastAt = time;

    const acceleration = motion.accelerationIncludingGravity ?? motion.acceleration;
    if (acceleration !== null && typeof acceleration === 'object') {
        const x = acceleration.x ?? 0;
        const y = acceleration.y ?? 0;
        const z = acceleration.z ?? 0;

        if (Number.isFinite(x) && Number.isFinite(y) && Number.isFinite(z)) {
            add(state.motion.accel, Math.hypot(x, y, z));
        }
    }
};

/**
 * Install the passive listeners once. Safe to call from every collection path; a second
 * call is a no-op. Never throws.
 */
export function startBehaviorCollection(): void {
    if (state.started || typeof window === 'undefined' || typeof document === 'undefined') {
        return;
    }

    state.started = true;
    state.startedAt = now();

    listen(window, 'pointermove', onPointer);
    listen(window, 'pointerdown', onPointer);
    listen(window, 'pointerup', onPointer);
    listen(window, 'pointercancel', onPointer);
    listen(window, 'pointerrawupdate', onPointerRaw);
    listen(window, 'touchstart', onTouch);
    listen(window, 'touchmove', onTouch);
    listen(window, 'touchend', onTouch);
    listen(window, 'touchcancel', onTouch);
    listen(window, 'keydown', onKey);
    listen(window, 'keyup', onKey);
    listen(window, 'wheel', onWheel);
    listen(window, 'scroll', () => {
        state.events.scroll += 1;
    });
    listen(window, 'focus', () => {
        state.events.focus += 1;
    });
    listen(window, 'blur', () => {
        state.events.blur += 1;
    });
    listen(document, 'copy', () => {
        state.events.copy += 1;
    });
    listen(document, 'cut', () => {
        state.events.cut += 1;
    });
    listen(document, 'paste', () => {
        state.events.paste += 1;
    });
    listen(document, 'selectionchange', () => {
        state.events.selection += 1;
    });
    listen(document, 'visibilitychange', () => {
        state.events.visibility += 1;
    });
    listen(window, 'devicemotion', onMotion);
    listen(window, 'deviceorientation', () => {
        state.motion.orientation += 1;
    });
}

/** Whether any input or sensor event has arrived. Visibility/focus alone are not input. */
export function hasBehaviorData(): boolean {
    return (
        state.pointer.moves +
            state.pointer.downs +
            state.touch.starts +
            state.keyboard.down +
            state.wheel.count +
            state.motion.events >
        0
    );
}

/**
 * Snapshot the aggregates. Returns `unavailable` when there has been no input at all, so
 * an empty page does not hash as two devices agreeing on a default.
 */
export function behavior(): ProbeResult<Record<string, unknown>> {
    if (!state.started) {
        startBehaviorCollection();
    }

    if (!hasBehaviorData()) {
        return unavailable('no-interaction');
    }

    return ok({
        elapsedMs: round(now() - state.startedAt),
        pointer: {
            moves: state.pointer.moves,
            downs: state.pointer.downs,
            ups: state.pointer.ups,
            cancels: state.pointer.cancels,
            raw: state.pointer.raw,
            types: [...state.pointer.types].sort(),
            coalesced: snapshotStats(state.pointer.coalesced),
            coalescedMax: state.pointer.coalescedMax,
            pressure: snapshotStats(state.pointer.pressure),
            width: snapshotStats(state.pointer.width),
            height: snapshotStats(state.pointer.height),
            tiltX: snapshotStats(state.pointer.tiltX),
            tiltY: snapshotStats(state.pointer.tiltY),
            twist: snapshotStats(state.pointer.twist),
            path: round(state.pointer.path),
            speed: snapshotStats(state.pointer.speed),
        },
        touch: {
            starts: state.touch.starts,
            moves: state.touch.moves,
            ends: state.touch.ends,
            force: snapshotStats(state.touch.force),
            radiusX: snapshotStats(state.touch.radiusX),
            radiusY: snapshotStats(state.touch.radiusY),
            altitude: snapshotStats(state.touch.altitude),
            azimuth: snapshotStats(state.touch.azimuth),
            interval: snapshotStats(state.touch.interval),
        },
        keyboard: {
            down: state.keyboard.down,
            up: state.keyboard.up,
            repeat: state.keyboard.repeat,
            codeCount: state.keyboard.codes.size,
            codesHash: fnv1a32([...state.keyboard.codes].sort().join('|')),
            locationCount: state.keyboard.locations.size,
            dwell: snapshotStats(state.keyboard.dwell),
            flight: snapshotStats(state.keyboard.flight),
        },
        wheel: {
            count: state.wheel.count,
            modes: [...state.wheel.modes].sort(),
            deltaAbs: snapshotStats(state.wheel.deltaAbs),
            deltaY: snapshotStats(state.wheel.deltaY),
            deltaX: snapshotStats(state.wheel.deltaX),
        },
        motion: {
            events: state.motion.events,
            orientation: state.motion.orientation,
            intervals: snapshotStats(state.motion.intervals),
            accel: snapshotStats(state.motion.accel),
        },
        events: { ...state.events },
    });
}

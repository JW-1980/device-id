/**
 * The native-function invariants (CreepJS `src/lies`, catalogue §1; contract §I1), as a module
 * with no dependencies.
 *
 * Moved out of integrity.ts so that phantom.ts can check the fresh realm's own
 * `Function.prototype.toString` with the same invariants (`realm-tampered`) without an import
 * cycle (integrity.ts imports phantom.ts). integrity.ts re-exports everything here.
 */

/**
 * The conformance invariants every native function satisfies, in the order they are run
 * and reported. Each is a lie code when violated.
 */
export const LIE_CODES = [
    'new_instance',
    'prototype_in',
    'own_keys',
    'descriptor_keys',
    'to_string',
    'object_to_string',
    'proto_cycle',
    'arguments_access',
] as const;

export type LieCode = (typeof LIE_CODES)[number];

/**
 * A native function's source as every engine in the matrix writes it. Measured, all 25
 * targets: Chromium `function get userAgent() { [native code] }` / `function toString() {
 * [native code] }`; Firefox and WebKit `function userAgent() {\n    [native code]\n}` (no
 * `get `, multi-line). The captured name must be the target's own member name in all three,
 * which is what rejects a bound function (`function () { [native code] }`) and a `Proxy`
 * (V8 prints an empty name for one).
 */
const NATIVE_SOURCE = /^function (?:get )?([\w$]*)\(\) \{\s*\[native code\]\s*\}$/;

/**
 * Whether `error` is a TypeError, read structurally: an error thrown by another realm's
 * function is not `instanceof` this realm's TypeError (CreepJS reads `constructor.name` for
 * the same reason).
 */
function isTypeError(error: unknown): boolean {
    try {
        return typeof error === 'object' && error !== null && (error as { name?: unknown }).name === 'TypeError';
    } catch {
        return false;
    }
}

const throwsTypeError = (action: () => unknown): boolean => {
    try {
        action();
        return false;
    } catch (error) {
        return isTypeError(error);
    }
};

/**
 * `proto_cycle`: `Object.setPrototypeOf(fn, Object.create(fn))` must throw a TypeError.
 *
 * For an ordinary function the cycle check walks the new prototype chain, meets `fn`, and
 * refuses BEFORE anything is changed — so on a native function this mutates nothing. For a
 * `Proxy`, the walk stops at the proxy (its [[GetPrototypeOf]] is not ordinary), the cycle
 * goes undetected and the target's prototype IS replaced: that is the tell (CreepJS "too much
 * recursion", catalogue §1), and the prototype is restored at once — to the one read before
 * the attempt, or to `Function.prototype` if that restore fails. Nothing may look a property
 * up on `fn` in between: its chain is cyclic until the restore.
 *
 * Only attempted on an extensible function (every native function is; on a frozen one
 * `setPrototypeOf` would throw for a different reason and the check proves nothing).
 */
function protoCycleLies(fn: object): boolean {
    if (!Object.isExtensible(fn)) {
        return false;
    }

    let original: object | null = Function.prototype;
    try {
        original = Object.getPrototypeOf(fn) as object | null;
    } catch {
        // A getPrototypeOf trap that throws: restore to Function.prototype below.
    }

    try {
        Object.setPrototypeOf(fn, Object.create(fn) as object);
    } catch (error) {
        // A native throws TypeError ("Cyclic __proto__ value"). Anything else — a trap
        // that throws its own error — is not native behaviour.
        return !isTypeError(error);
    }

    try {
        Object.setPrototypeOf(fn, original);
    } catch {
        try {
            Object.setPrototypeOf(fn, Function.prototype);
        } catch {
            // Neither restore was accepted: only a trap can refuse both, and the lie is
            // recorded either way. Throwing here would abort the collection.
        }
    }

    return true;
}

/**
 * The lie codes `fn` violates. `expectedName` is the member name its native source must
 * carry. Never throws: an invariant whose own evaluation throws counts as violated (native
 * functions evaluate every one of them without throwing, measured in all three engines).
 */
export function lieCodesOf(fn: (...args: never[]) => unknown, expectedName: string): LieCode[] {
    const anyFn = fn as unknown as Record<string, unknown> & (new () => unknown);
    const checks: Record<LieCode, () => boolean> = {
        new_instance: () => !throwsTypeError(() => new anyFn()),
        prototype_in: () => 'prototype' in anyFn,
        own_keys: () => Object.getOwnPropertyNames(fn).sort().join() !== 'length,name',
        descriptor_keys: () => Object.keys(Object.getOwnPropertyDescriptors(fn)).sort().join() !== 'length,name',
        to_string: () => {
            const match = NATIVE_SOURCE.exec(Function.prototype.toString.call(fn));
            return match === null || match[1] !== expectedName;
        },
        object_to_string: () => !throwsTypeError(() => (Object.create(fn) as { toString(): unknown }).toString()),
        proto_cycle: () => protoCycleLies(fn),
        arguments_access: () => !throwsTypeError(() => anyFn.arguments),
    };

    const codes: LieCode[] = [];
    for (const code of LIE_CODES) {
        let lied: boolean;
        try {
            lied = checks[code]();
        } catch {
            lied = true;
        }
        if (lied) codes.push(code);
    }

    return codes;
}

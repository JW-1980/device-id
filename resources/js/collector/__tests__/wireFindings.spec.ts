/**
 * Integrity findings on the wire are bare codes (notes/24 finding F3, recommendation R4).
 *
 * The client used to attach an English `detail` sentence to every finding. The server never
 * read it (EnvironmentConsistency::fromIntegrity lifts by code and writes its own sentence;
 * DeviceComponents::untrusted reads `code`; ConfidenceScorer counts entries), so it was ~1.7 KB
 * of shipped prose explaining each check, plus attacker-controllable free text on the wire.
 *
 * These tests drive the public collection functions on a deliberately tampered page, so that
 * findings from both integrity phases are present, and assert on the serialised body exactly as
 * it is posted: every finding is `{ code }` and nothing else, and the codes are the closed set.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { collect, collectForIdentity, collectTier2 } from '@device-id/collector/index';
import { INTEGRITY_CODES } from '@device-id/collector/integrity';
import type { Challenge } from '@device-id/collector/protocol';
import { buildEnvelope } from '@device-id/collector/transport';

const undos: Array<() => void> = [];
afterEach(() => {
    vi.restoreAllMocks();
    while (undos.length) undos.pop()?.();
});

function defineOwn(target: object, name: string, descriptor: PropertyDescriptor): void {
    const original = Object.getOwnPropertyDescriptor(target, name);
    Object.defineProperty(target, name, { configurable: true, ...descriptor });
    undos.push(() => {
        if (original) Object.defineProperty(target, name, original);
        else delete (target as Record<string, unknown>)[name];
    });
}

/**
 * A page with tampering each phase detects: two navigator attributes shadowed by own
 * properties (`descriptor_shadowed` x2), a patched `Math.tanh` (`math_pf_mismatch`), and a
 * `Function.prototype.toString` that lies about a fake `Screen.width` getter, which the
 * deferred phase's fresh realm sees through (`realm_tostring_mismatch`). jsdom adds
 * `lie_battery_failed` and `webdriver_missing` on its own.
 */
function tamper(): void {
    defineOwn(navigator, 'userAgent', { value: 'Mozilla/5.0 (Spoofed)' });
    defineOwn(navigator, 'hardwareConcurrency', { value: 64 });
    defineOwn(Math, 'tanh', { value: () => 0.5, writable: true });

    const fake = (): number => 1920;
    defineOwn(Screen.prototype, 'width', { get: fake });
    const pristine = Function.prototype.toString;
    const lying = function toString(this: unknown): string {
        return this === fake ? 'function get width() { [native code] }' : pristine.call(this);
    };
    defineOwn(Function.prototype, 'toString', { value: lying, writable: true });
}

const CHALLENGE: Challenge = { token: 'wire-token', purpose: 'signin', expiresAt: Date.now() + 60_000 };
const KNOWN_CODES: ReadonlySet<string> = new Set(Object.values(INTEGRITY_CODES));

/** The findings exactly as the server receives them: through JSON, not the in-memory objects. */
function findingsOnTheWire(body: unknown): Array<Record<string, unknown>> {
    const parsed = JSON.parse(JSON.stringify(body)) as { claims: { integrity: { findings: Array<Record<string, unknown>> } } };
    return parsed.claims.integrity.findings;
}

function expectBareCodes(findings: Array<Record<string, unknown>>): void {
    for (const finding of findings) {
        expect(Object.keys(finding)).toEqual(['code']);
        expect(KNOWN_CODES.has(finding.code as string)).toBe(true);
    }
}

describe('integrity findings on the wire', () => {
    it('the tier-1 envelope carries each synchronous finding as a bare code, one entry per occurrence', async () => {
        tamper();

        const result = await collect(CHALLENGE, 'signin');
        const body = buildEnvelope({ challenge: CHALLENGE, slot: 'tier1', digest: result.digest, claims: result.claims });
        const findings = findingsOnTheWire(body);

        const codes = findings.map((finding) => finding.code);
        // Two shadowed attributes are two entries: the server's penalty counts them.
        expect(codes.filter((code) => code === INTEGRITY_CODES.DESCRIPTOR_SHADOWED)).toHaveLength(2);
        expect(codes).toContain(INTEGRITY_CODES.MATH_PF_MISMATCH);
        expect(codes).toContain(INTEGRITY_CODES.LIE_BATTERY_FAILED);
        expectBareCodes(findings);
        expect(JSON.stringify(body)).not.toMatch(/"detail"\s*:/);
    });

    it('the tier-2 envelope carries the deferred (phantom-realm) finding as a bare code', async () => {
        tamper();

        const result = await collectTier2(CHALLENGE, 'signin');
        const body = buildEnvelope({ challenge: CHALLENGE, slot: 'tier2', digest: result.digest, claims: result.claims });
        const findings = findingsOnTheWire(body);

        expect(findings).toEqual([{ code: INTEGRITY_CODES.REALM_TOSTRING_MISMATCH }]);
        expect(JSON.stringify(body)).not.toMatch(/"detail"\s*:/);
    });

    it('the identify-path body carries both phases as bare codes', async () => {
        tamper();

        const claims = await collectForIdentity(15_000, []);
        const findings = findingsOnTheWire({ v: claims.v, claims });

        const codes = findings.map((finding) => finding.code);
        expect(codes).toContain(INTEGRITY_CODES.DESCRIPTOR_SHADOWED);
        expect(codes).toContain(INTEGRITY_CODES.REALM_TOSTRING_MISMATCH);
        expect(findings.length).toBeGreaterThanOrEqual(5);
        expectBareCodes(findings);
        expect(JSON.stringify(claims)).not.toMatch(/"detail"\s*:/);
    });
});

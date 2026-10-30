<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Scoring;

use NutriCompare\Fingerprint\ProbeRegistry;
use NutriCompare\Fingerprint\Support\Verdict;

/**
 * The omission gate: a sign-up or password reset whose envelopes simply LEAVE OUT many of
 * the probes the collector was told to run is challenged — never blocked (anti-fraud review,
 * owner decision 2026-10-05).
 *
 * ## The attack
 *
 * An HTTP replay bot posts a captured honest claim set with matching headers and every newer
 * probe removed. Every rule is silent on absence (missing data is never evidence), so it
 * scores 0 and `pass`. Omission is free.
 *
 * ## Why this does not re-create notes/07 §1
 *
 * notes/07's check read "no subresources" as "scraper", and a warm-cache honest visitor
 * produced the same observation. The question is always: does an honest client ever
 * produce this observation? Three candidate measures, and why two are refused:
 *
 * - `confidence` (ConfidenceScorer) gives `unavailable` half credit and charges an absent
 *   tier 2. A browser that legitimately lacks an API (WebKit without `requestIdleCallback`,
 *   Firefox without UA Client Hints, RFP/Tor/Brave refusing canvas or workers) answers
 *   `unavailable`, and a visitor who submits the form before idle time never sends tier 2.
 *   Gating on confidence would challenge exactly those people. Refused.
 * - "tier 2 missing" is what a fast honest visitor produces. Refused: an envelope that was
 *   never sent is never counted.
 * - **A probe key ABSENT from an envelope that WAS sent** — this is what is measured. The
 *   collector builds each envelope all-or-nothing: every enabled probe of that envelope is
 *   present, as its value or as `{state: 'unavailable'|'error'}` when it could not run
 *   (`resolveAll`/`unwrapForWire` in index.ts, `probe()` in canonical.ts never throws), and
 *   an oversized envelope is not sent at all (transport.ts). Measured on 2026-10-05 with
 *   the real collector in Chromium 153, Firefox 155, Firefox 155 with
 *   `privacy.resistFingerprinting` and WebKit 26.6: 0 absent keys in either envelope, with
 *   `unavailable` answers (Firefox `gpuMath`, RFP `canvasDual`) counted as reported.
 *
 * Only probes the operator has NOT switched off are expected (`ProbeRegistry` policy; the
 * collector skips a disabled probe, so its absence is the policy, not an omission). The
 * policy is the UNION of the one the challenge was issued under and the current one
 * (`FingerprintIngest`): a probe switched off mid-challenge is neither scored nor expected.
 *
 * Only probes the client's BUNDLE knows are expected either. The envelope carries the
 * collector's probe-set marker (`probes`, protocol.ts `PROBE_SET`); a body without one is a
 * bundle from before the marker existed and is judged against the probe set that bundle
 * shipped (`ProbeRegistry::PROBE_SET_ADDED`), so an honest page left open across a deploy
 * is not challenged for probes its code never had (sceptical review round 4: the bundle on
 * `main` omits 12 of the 43 probes the current one sends, 72 % reported).
 *
 * A key that is present with a `null` value is NOT a report: the collector never sends null
 * (every probe answers a value or `{state: 'unavailable'|'error'}`; captured from the real
 * collector, tests/Fixtures/fingerprint/envelope-shapes.json — Chromium on 2026-10-12; the
 * same held in Firefox, Firefox with resistFingerprinting and WebKit on 2026-10-06), and
 * `ConfidenceScorer` already calls it absent. The same holds for a `{state}` tag that is not
 * one of the three the collector writes, and for `{state: 'ok'}` without a value (security
 * review round 4: 19 keys set to null passed as 19 reports).
 *
 * ## What it measures
 *
 * Per envelope that arrived, the expected names and the absent ones:
 *
 * - tier 1 envelope: every tier-1 probe in `claims.tier1`, and every integrity probe except
 *   the deferred-only `phantomRealm` in `claims.integrity.data`;
 * - tier 2 envelope: every tier-2 and hardware probe in `claims.tier2`, and the deferred
 *   integrity phase (`phantomRealm`, `resistance`, `canvasFill`) in `claims.integrity.data`.
 *
 * `reported` = expected − absent, PER ENVELOPE. The gate fires when any envelope that
 * arrived has `reported × 100 < min_reported × expected` (integer arithmetic, no rounding at
 * the boundary) for a gated purpose. Per envelope, not pooled (sceptical review round 4):
 * pooled, a replay that dropped six tier-1 probes — the integrity data `IntegrityFindings`
 * derives its findings from — was cleared by appending the captured complete tier 2. A
 * later envelope can therefore raise the decision, never lower it.
 *
 * ## What it does, and what it never does
 *
 * - It never changes the risk SCORE (HOW-IT-WORKS §4.3: confidence must never change the
 *   risk score). It adds a weight-0 disagreement `confidence_omission`, so the score is
 *   still reconstructible from the disagreements, and raises the band to `challenge` when it
 *   is below that. A `block` band stays `block`; the gate can never produce `block`.
 * - It only runs for the purposes `omission_gate_purposes` lists (sign-up and password reset
 *   by default; sign-in is deliberately not one — see config/security.php). The purpose is
 *   the one the CLIENT asked the challenge for (`FingerprintController::challenge`), so on
 *   its own it decides nothing: a bot asks for `signin` and is measured but never gated.
 *   The band is only meaningful to a consumer that redeems the observation for the purpose
 *   it is acting on (HOW-IT-WORKS §4.3, the consumer contract). Its one reader, the
 *   contribution trust model (`TrustFeatures`, a member's latest submitted band), was retired on
 *   2026-10-12 (option A, docs/design/CONTRIBUTOR_TRUST.md §1a); no consumer redeems it yet.
 * - With the gate switched off the measurement is still taken, stored on the observation
 *   (`probe_states.omission`) and logged, so a deployment can watch it before enabling.
 *
 * ## What it does not stop, stated rather than hidden
 *
 * A client that sends `{state: 'unavailable'}` for every probe it does not want to run, a
 * client that declines, and a client that runs no JavaScript at all are each
 * indistinguishable from an honest browser that could not measure, and none of them is
 * challenged here — that is "missing data is never evidence" again, and it is correct. The
 * gate removes the cheapest variant (a replayed honest claim set with probes dropped, which
 * keeps the honest device identity and a `pass`), not the class.
 */
final class ProbeOmission
{
    /** The disagreement code the gate records. Weight 0: it never moves the score. */
    public const CODE = 'confidence_omission';

    /**
     * Integrity probes run ONLY by the deferred phase (integrity.ts `collectDeferredIntegrity`),
     * so they are not expected in the tier-1 envelope.
     *
     * @var list<string>
     */
    public const DEFERRED_ONLY_INTEGRITY = ['phantomRealm'];

    /**
     * Integrity probes the deferred phase reports in the tier-2 envelope (integrity.ts
     * `collectDeferredIntegrity`: `phantomRealm`, plus `resistance` and `canvasFill`
     * re-measured for that envelope's own trust decisions).
     *
     * @var list<string>
     */
    public const DEFERRED_INTEGRITY = ['phantomRealm', 'resistance', 'canvasFill'];

    public const SLOT_TIER1 = 'tier1';

    public const SLOT_TIER2 = 'tier2';

    /**
     * The measurement for one envelope: which `location:name` entries were expected and
     * which of them were absent.
     *
     * @param  array<array-key, mixed>  $claims  the envelope's claims, after the disabled probes were stripped
     * @param  list<string>  $disabled  the operator's switched-off probes
     * @param  int  $probeSet  the probe set the client's bundle reports (`ProbeRegistry::probeSet()`)
     * @return array{expected: int, omitted: list<string>, probe_set: int}
     */
    public static function measure(array $claims, string $slot, array $disabled, int $probeSet = ProbeRegistry::PROBE_SET): array
    {
        $probeSet = ProbeRegistry::probeSet($probeSet);
        $expected = self::expectedFor($slot, $disabled, $probeSet);
        $omitted = [];

        foreach ($expected as $entry) {
            [$location, $name] = explode(':', $entry, 2);
            $container = $location === 'integrity'
                ? self::unwrap(self::unwrap($claims['integrity'] ?? null)['data'] ?? null)
                : self::unwrap($claims[$location] ?? null);

            if (! array_key_exists($name, $container) || ! self::isReport($container[$name])) {
                $omitted[] = $entry;
            }
        }

        return ['expected' => count($expected), 'omitted' => $omitted, 'probe_set' => $probeSet];
    }

    /**
     * Whether one probe node is something the collector writes: a non-null value, or a
     * `{state}` tag it uses — `unavailable`/`error`, or `ok` with a non-null `value` (the
     * integrity results). `null` and any other tag are what `ConfidenceScorer` calls absent.
     */
    public static function isReport(mixed $node): bool
    {
        if ($node === null) {
            return false;
        }

        if (! is_array($node) || ! array_key_exists('state', $node)) {
            return true;
        }

        return match ($node['state']) {
            ConfidenceScorer::STATE_OK => ($node['value'] ?? null) !== null,
            ConfidenceScorer::STATE_UNAVAILABLE, 'error' => true,
            default => false,
        };
    }

    /**
     * The `location:name` entries an honest collector puts in one envelope under this policy.
     *
     * @param  list<string>  $disabled
     * @return list<string>
     */
    public static function expectedFor(string $slot, array $disabled, int $probeSet = ProbeRegistry::PROBE_SET): array
    {
        $off = array_fill_keys($disabled, true);
        $out = [];

        foreach (ProbeRegistry::methods($probeSet) as $name => $method) {
            if (! $method['core'] && isset($off[$name])) {
                continue;
            }

            $tier = $method['tier'];

            if ($slot === self::SLOT_TIER1) {
                if ($tier === ProbeRegistry::TIER_ONE) {
                    $out[] = 'tier1:'.$name;
                } elseif ($tier === ProbeRegistry::TIER_INTEGRITY && ! in_array($name, self::DEFERRED_ONLY_INTEGRITY, true)) {
                    $out[] = 'integrity:'.$name;
                }

                continue;
            }

            if ($tier === ProbeRegistry::TIER_TWO || $tier === ProbeRegistry::TIER_HARDWARE) {
                $out[] = 'tier2:'.$name;
            } elseif ($tier === ProbeRegistry::TIER_INTEGRITY && in_array($name, self::DEFERRED_INTEGRITY, true)) {
                $out[] = 'integrity:'.$name;
            }
        }

        return $out;
    }

    /**
     * Merge a later envelope's measurement into the stored per-slot record. A slot already
     * measured is replaced (a slot is redeemable once, so this only happens on a retry of
     * the same body).
     *
     * @param  array<array-key, mixed>  $stored  `probe_states.omission` as stored
     * @param  array{expected: int, omitted: list<string>, probe_set?: int}  $measurement
     * @return array<string, array{expected: int, omitted: list<string>, probe_set?: int}>
     */
    public static function record(array $stored, string $slot, array $measurement): array
    {
        $out = [];

        foreach ([self::SLOT_TIER1, self::SLOT_TIER2] as $known) {
            $entry = $stored[$known] ?? null;
            if (! is_array($entry) || ! is_int($entry['expected'] ?? null) || ! is_array($entry['omitted'] ?? null)) {
                continue;
            }
            $out[$known] = [
                'expected' => max(0, $entry['expected']),
                'omitted' => array_values(array_filter($entry['omitted'], 'is_string')),
            ];
            if (is_int($entry['probe_set'] ?? null)) {
                $out[$known]['probe_set'] = $entry['probe_set'];
            }
        }

        $out[$slot] = $measurement;

        return $out;
    }

    /**
     * The totals over every envelope recorded.
     *
     * @param  array<string, array{expected: int, omitted: list<string>, probe_set?: int}>  $record
     * @return array{expected: int, omitted: int, reported_percent: int|null}
     */
    public static function totals(array $record): array
    {
        $expected = 0;
        $omitted = 0;

        foreach ($record as $entry) {
            $expected += $entry['expected'];
            $omitted += min($entry['expected'], count($entry['omitted']));
        }

        return [
            'expected' => $expected,
            'omitted' => $omitted,
            // Floored, for display and logs; the gate itself compares integers exactly.
            'reported_percent' => $expected > 0 ? intdiv(100 * ($expected - $omitted), $expected) : null,
        ];
    }

    /**
     * Whether the gate fires for this record under these settings: some envelope that arrived
     * reported less than the minimum. Pure, so the decision is testable without a database.
     *
     * @param  array<string, array{expected: int, omitted: list<string>, probe_set?: int}>  $record
     * @param  array{enabled: bool, min_reported: int, purposes: list<string>}  $settings
     */
    public static function fires(array $record, string $purpose, array $settings): bool
    {
        if (! $settings['enabled'] || ! in_array($purpose, $settings['purposes'], true)) {
            return false;
        }

        foreach ($record as $entry) {
            $expected = $entry['expected'];
            if ($expected < 1) {
                continue;
            }

            // A stored record whose omitted list is longer than its expected count (a corrupted
            // row) gives a negative share here, which fires exactly like "nothing reported"
            // (`min_reported` is at least 1), so no clamp is needed for the decision.
            $reported = $expected - count($entry['omitted']);

            if ($reported * 100 < $settings['min_reported'] * $expected) {
                return true;
            }
        }

        return false;
    }

    /**
     * The verdict with the gate applied: any previous `confidence_omission` entry removed (a
     * tier-2 envelope re-decides over the per-envelope record, in which the tier-1 envelope's
     * measurement is kept, so a decision is never lowered), then, when the gate fires, a weight-0
     * entry added and the band raised to at least `challenge`. The score is never changed
     * and the band is never raised to `block`.
     *
     * @param  array<string, array{expected: int, omitted: list<string>, probe_set?: int}>  $record
     * @param  array{enabled: bool, min_reported: int, purposes: list<string>}|null  $settings  read from the store when null
     */
    public static function apply(Verdict $verdict, array $record, string $purpose, ?array $settings = null): Verdict
    {
        $settings ??= OmissionGateSettings::current();

        $disagreements = array_values(array_filter(
            $verdict->disagreements,
            static fn (array $d): bool => $d['code'] !== self::CODE,
        ));
        $reasons = array_values(array_filter($verdict->reasons, static fn (string $r): bool => $r !== self::CODE));
        // The caller passes the band the risk score alone gives (the scorer's verdict at tier
        // 1, `mergedVerdict()` recomputed from the score at tier 2), so an earlier
        // application of this gate never survives a re-decision.
        $band = $verdict->band;

        if (self::fires($record, $purpose, $settings)) {
            $totals = self::totals($record);
            $disagreements[] = [
                'code' => self::CODE,
                // Counts only: never a probe value, and the names stay on the observation's
                // `probe_states`, not in prose.
                'detail' => sprintf(
                    '%d of %d probes the collector was asked to run were absent from the envelopes it sent; at least one envelope reported less than the minimum (%d%%).',
                    $totals['omitted'],
                    $totals['expected'],
                    $settings['min_reported'],
                ),
                'weight' => 0,
            ];
            $reasons[] = self::CODE;
            sort($reasons, SORT_STRING);

            if ($band === Verdict::BAND_PASS || $band === Verdict::BAND_ELEVATED) {
                $band = Verdict::BAND_CHALLENGE;
            }
        }

        return new Verdict(
            $band,
            $verdict->score,
            $reasons,
            $disagreements,
            $verdict->deviceKey,
            $verdict->saltVersion,
            $verdict->confidence,
        );
    }

    /**
     * A container's probes: the array itself, or the `value` of a `{state, value}` envelope.
     *
     * @return array<array-key, mixed>
     */
    private static function unwrap(mixed $node): array
    {
        if (is_array($node) && array_key_exists('state', $node) && array_key_exists('value', $node)) {
            $node = $node['value'];
        }

        return is_array($node) ? $node : [];
    }
}

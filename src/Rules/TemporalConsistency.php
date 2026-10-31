<?php

declare(strict_types=1);

namespace DeviceId\Rules;

use DeviceId\Scoring\VerdictScorer;
use DeviceId\Support\PreviousObservation;
use DeviceId\Support\TransportFinding;
use DeviceId\Support\TransportIntegrityResult;

/**
 * Consistency across observations of one device: observation N against N-1.
 *
 * One rule, `temporal_ja4_changed_without_ua_change`: the TLS stack (JA4 section b and
 * section a with its extension count masked; see `stackChanged()`) differs from the
 * previous observation's while the reported User-Agent summary is identical. A browser
 * update changes both; a TLS-intercepting proxy or a swapped stack changes one. TLS
 * resumption changes section c and the extension count only (notes/14) and is ignored,
 * and so is a TCP↔QUIC switch (`t` against `q` is never compared). Any null on either
 * side is silence. Soft, weight 25.
 */
final readonly class TemporalConsistency
{
    /** Stored as `transport_temporal_ja4_changed_without_ua_change` (VerdictScorer prefixes). */
    public const JA4_CHANGED_WITHOUT_UA_CHANGE = 'temporal_ja4_changed_without_ua_change';

    /** Stored as `transport_temporal_hard_component_changed`. */
    public const HARD_COMPONENT_CHANGED = 'temporal_hard_component_changed';

    /** One observation back: a wider window fires on honest browsers that updated. */

    /**
     * Findings for a new observation, given the device's previous one.
     *
     * Returns an empty list rather than null, so the caller concatenates rather than
     * branching — and so that "no previous row" and "previous row disagreed" are the same
     * shape to handle, which they are: both mean nothing to add.
     *
     * @param  string|null  $userAgentSummary  what THIS observation reported
     * @param  string|null  $blockTuple  `DeviceComponents::blockTuple()` of THIS observation (null when a hard component is unknown)
     * @return list<TransportFinding>
     */
    public function findings(
        ?PreviousObservation $previous,
        ?TransportIntegrityResult $transport,
        ?string $userAgentSummary,
        ?string $blockTuple = null,
    ): array {
        if ($previous === null) {
            return [];
        }

        return [
            ...$this->ja4Findings($previous, $transport, $userAgentSummary),
            ...$this->hardComponentFindings($previous, $blockTuple),
        ];
    }

    /**
     * `temporal_hard_component_changed`: the OS family, CPU architecture or touch class (the HARD
     * components) differ from the previous observation of the SAME cookie or browser key. A
     * physical device cannot change them; a User-Agent switch, an emulator or a cookie replayed on
     * another machine can. Compared through `DeviceComponents::blockTuple()`, the unkeyed hash the
     * host already stores, so nothing new is kept. Either side null (a hard component unknown) is
     * silence, never a difference.
     *
     * Only meaningful when the host chose `$previous` by the cookie or the browser key. A host that
     * picks it through the matcher's own candidates gets the same tuple by construction (the
     * candidate query blocks on it), and the rule stays silent rather than wrong.
     *
     * @return list<TransportFinding>
     */
    private function hardComponentFindings(PreviousObservation $previous, ?string $blockTuple): array
    {
        if ($blockTuple === null || $blockTuple === '' || $previous->blockTuple === null || $previous->blockTuple === '') {
            return [];
        }

        if (hash_equals($previous->blockTuple, $blockTuple)) {
            return [];
        }

        return [
            TransportFinding::soft(
                self::HARD_COMPONENT_CHANGED,
                'The operating system, CPU architecture or touch class changed since the previous observation of the same cookie or browser key.',
            ),
        ];
    }

    /**
     * @return list<TransportFinding>
     */
    private function ja4Findings(PreviousObservation $previous, ?TransportIntegrityResult $transport, ?string $userAgentSummary): array
    {
        $ja4 = $transport?->witnessString('ja4');

        // Either side missing means there is nothing to compare. See the class docblock:
        // "we cannot tell" is the truth in all three of the ordinary situations listed
        // there, and treating it as suspicion is the mistake this whole feature has been
        // bitten by before.
        if ($ja4 === null || $ja4 === '' || $previous->ja4Correlator === null || $previous->ja4Correlator === '') {
            return [];
        }

        if ($previous->ja4Correlator === $ja4) {
            return [];
        }

        // TLS resumption changes section c (and the extension count in section a) for
        // every engine, and QUIC changes the whole value, so a changed c alone is not a
        // changed stack. The stack is judged to have changed only when BOTH the cipher
        // hash (section b) AND section a with its extension count masked differ.
        if (! self::stackChanged($previous->ja4Correlator, $ja4)) {
            return [];
        }

        // The escape hatch that makes the whole rule usable. A changed UA string explains
        // a changed ClientHello: the browser updated. A byte-identical UA does not.
        //
        // Both sides must be non-empty. Two absent UA summaries are not evidence that the
        // browser is unchanged — they are evidence that we recorded nothing either time,
        // and "we know nothing twice" is not "we know it is the same".
        $before = $previous->userAgentSummary;
        $now = $userAgentSummary;

        if ($before === null || $before === '' || $now === null || $now === '') {
            return [];
        }

        if ($before !== $now) {
            return [];
        }

        return [
            TransportFinding::soft(
                self::JA4_CHANGED_WITHOUT_UA_CHANGE,
                'The TLS ClientHello correlator changed since the previous observation while the reported browser did not.',
            ),
        ];
    }

    /**
     * Do two JA4 values describe different TLS stacks, as opposed to one stack resumed?
     *
     * Compared like with like: a TCP (`t…`) and a QUIC (`q…`) value are never compared,
     * because Chromium moves between h2 and h3 as `Alt-Svc` and UDP reachability dictate
     * and QUIC offers a different cipher set by construction (round-2 WS2-3). Within one
     * transport, section a with the two extension-count digits masked (`t13d15__h2`) and
     * section b must both differ. Either side unparseable (an old 23-character row has no
     * section c but still parses into a and b) compares as unchanged.
     */
    public static function stackChanged(string $previous, string $current): bool
    {
        $before = self::sections($previous);
        $now = self::sections($current);

        if ($before === null || $now === null) {
            return false;
        }

        if ($before[0][0] !== $now[0][0]) {
            return false;
        }

        return $before[0] !== $now[0] && $before[1] !== $now[1];
    }

    /**
     * @return array{0: string, 1: string}|null `[a with the extension count masked, b]`
     */
    private static function sections(string $ja4): ?array
    {
        $parts = explode('_', strtolower(trim($ja4)));
        if (count($parts) < 2 || strlen($parts[0]) !== 10 || $parts[1] === '') {
            return null;
        }

        return [substr($parts[0], 0, 6).'__'.substr($parts[0], 8), $parts[1]];
    }

    /**
     * The most recent observation of a device, or null. Ordered by `created_at` then `id`
     * so the `[fingerprint_device_id, created_at]` index serves the query; `id` breaks
     * same-second ties.
     */
}

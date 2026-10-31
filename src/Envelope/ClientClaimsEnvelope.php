<?php

declare(strict_types=1);

namespace DeviceId\Envelope;

use DeviceId\Support\Config;

/**
 * The claims body, parsed and validated. Never repaired: a parser that coerces or
 * defaults is one an attacker can steer, so every rejection rejects the whole body
 * with a named reason (logged, never returned).
 *
 * Wire shape (v3): `{ v, nonce, slot, digest, claims, probes? }`. `slot` is `tier1` or
 * `tier2` and selects which single-use slot of the challenge this envelope redeems; a v2
 * body (no `slot`) is read as `tier1` for one release of rolling deploy. `probes` is the
 * collector bundle's probe set (protocol.ts `PROBE_SET`, `ProbeRegistry::PROBE_SET`); absent
 * means a bundle from before the marker, judged against the legacy set; present, it must be
 * a positive integer. `purpose` is not read from the body or the query; the challenge
 * record is authoritative.
 *
 * There is no client MAC: freshness comes from the single-use-per-slot nonce and
 * session binding from the device cookie, both server-side. Nothing here proves the
 * claims are sincere — that is `EnvironmentConsistency`'s job.
 */
final readonly class ClientClaimsEnvelope
{
    /** The newest envelope version this build understands; higher is rejected. */
    public const SUPPORTED_VERSION = 3;

    /** The oldest version still accepted (no `slot`; read as tier 1). */
    public const MINIMUM_VERSION = 1;

    /**
     * The claim-body ceiling in bytes when `fingerprint.max_body_bytes` is unset or not a
     * number: the shipped config default and the collector's own `MAX_PAYLOAD_BYTES`. Floored
     * at 1 KiB on read. The application's `FingerprintSettings::DEFAULT_MAX_BODY_BYTES` is this
     * constant, so every body parser there falls back to the same number (client review CL3-9).
     */
    public const DEFAULT_MAX_BODY_BYTES = 24576;

    /**
     * @param  array<array-key, mixed>  $claims  the tier/integrity payload, shape-validated downstream
     * @param  string  $digest  the client's own hash; recorded for debugging, never trusted
     * @param  int  $bodyBytes  what the body weighed
     * @param  int|null  $probeSet  the bundle's `probes` marker, null when the body has none
     */
    private function __construct(
        public string $nonce,
        public int $version,
        public string $slot,
        public array $claims,
        public string $digest,
        public int $bodyBytes,
        public ?int $probeSet = null,
    ) {}

    public static function parse(string $body): EnvelopeParse
    {
        $maxBytes = max(1024, Config::int('fingerprint.max_body_bytes', self::DEFAULT_MAX_BODY_BYTES));

        if (strlen($body) > $maxBytes) {
            return EnvelopeParse::rejected('body_too_large');
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($body, true, 24, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return EnvelopeParse::rejected('malformed_json');
        }

        if (! is_array($decoded) || array_is_list($decoded)) {
            return EnvelopeParse::rejected('not_an_object');
        }

        $version = $decoded['v'] ?? null;
        if (! is_int($version) || $version < self::MINIMUM_VERSION) {
            return EnvelopeParse::rejected('missing_version');
        }
        if ($version > self::SUPPORTED_VERSION) {
            return EnvelopeParse::rejected('unsupported_version');
        }

        // `token` is the pre-v2 spelling; accepted for bundles still in a browser cache.
        $nonce = $decoded['nonce'] ?? $decoded['token'] ?? null;
        if (! is_string($nonce) || preg_match('/^[A-Za-z0-9_-]{43}$/', $nonce) !== 1) {
            return EnvelopeParse::rejected('missing_or_malformed_nonce');
        }

        $slot = $decoded['slot'] ?? null;
        if ($slot === null) {
            if ($version >= 3) {
                return EnvelopeParse::rejected('missing_slot');
            }
            $slot = Slot::TIER1;
        }
        if (! is_string($slot) || ! in_array($slot, Slot::ALL, true)) {
            return EnvelopeParse::rejected('malformed_slot');
        }

        $claims = $decoded['claims'] ?? null;
        if (! is_array($claims) || array_is_list($claims)) {
            return EnvelopeParse::rejected('missing_claims');
        }

        if (count($claims) > max(1, Config::int('fingerprint.max_claims', 200))) {
            return EnvelopeParse::rejected('too_many_claims');
        }

        // The top-level count above is five or six for every real envelope, so it bounds
        // nothing: 1,500 values nested under one key passed it (SK-15). The bound that
        // matters is the total number of leaves the server will canonicalise and hash.
        if (self::exceedsLeaves($claims, max(1, Config::int('fingerprint.max_claim_leaves', 1000)))) {
            return EnvelopeParse::rejected('too_many_claim_leaves');
        }

        $digest = $decoded['digest'] ?? '';
        if (! is_string($digest) || ! in_array(strlen($digest), [0, 64], true)) {
            return EnvelopeParse::rejected('malformed_digest');
        }

        $probeSet = $decoded['probes'] ?? null;
        if ($probeSet !== null && (! is_int($probeSet) || $probeSet < 1)) {
            return EnvelopeParse::rejected('malformed_probe_set');
        }

        return EnvelopeParse::accepted(
            new self($nonce, $version, $slot, $claims, $digest, strlen($body), $probeSet)
        );
    }

    /**
     * Whether the claim tree has more than `$limit` leaves.
     *
     * A leaf is a scalar, a null, or an EMPTY array: counting `{}`/`[]` as one keeps a
     * tree of empty containers from escaping the bound. Stops counting at the first leaf
     * over the limit, so the work is bounded by the limit and not by the input. Depth is
     * already bounded by `json_decode()` (24).
     *
     * Measured (2026-10-05, the shipped collector in Chromium 153 / Firefox 155 / WebKit
     * 26.6): the tier-1 claim set has 224 / 196 / 198 leaves and the tier-2 set 148 / 118 /
     * 140, against a default limit of 1,000.
     *
     * @param  array<array-key, mixed>  $tree
     */
    public static function exceedsLeaves(array $tree, int $limit): bool
    {
        $count = 0;
        $stack = [$tree];

        while ($stack !== []) {
            $node = array_pop($stack);

            if (! is_array($node) || $node === []) {
                if (++$count > $limit) {
                    return true;
                }

                continue;
            }

            foreach ($node as $child) {
                $stack[] = $child;
            }
        }

        return false;
    }

    public function isTier2(): bool
    {
        return $this->slot === Slot::TIER2;
    }

    /**
     * The claim set reduced to what the server scores: `v`, `purpose` and `timing` are
     * dropped here. `purpose` in particular is never trusted from the body.
     *
     * A tier-2 envelope keeps only `tier2` and `integrity`: the collector sends `tier1: {}`
     * there, and a `tier1` block in it could otherwise make the tier-2 envelope "prove" a
     * protection the tier-1 envelope did not, or overwrite tier-1 components in the merge
     * (security review round 4, F9).
     *
     * @return array<array-key, mixed>
     */
    public function signalClaims(): array
    {
        $claims = $this->claims;

        unset($claims['v'], $claims['purpose'], $claims['timing']);

        if ($this->isTier2()) {
            return array_intersect_key($claims, ['tier2' => true, 'integrity' => true]);
        }

        return $claims;
    }
}

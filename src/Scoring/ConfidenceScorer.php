<?php

declare(strict_types=1);

namespace DeviceId\Scoring;

use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Rules\IntegrityFindings;
use DeviceId\Support\Confidence;
use DeviceId\Support\Config;
use DeviceId\Support\ProbeEnvelope;
use DeviceId\Support\TransportIntegrityResult;

/**
 * Scores how much of the expected measurement surface answered (coverage, 1-100).
 *
 *     confidence = clamp(1, 100, round(100 * earned / expected) - penalties)
 *
 * `ok` earns the probe's full weight, `unavailable` half, absent earns `1 - charge`.
 * Tier-1 absence is charged in full; tier-2 absence at a quarter (the deferred tier is
 * often cut off by navigation), but only once at least half of tier 1 by weight answered.
 *
 * Penalties: `navigator.webdriver === true` (the environment is instrumented) and the
 * client's own integrity findings (capped). Neither touches the risk score.
 *
 * The weights are the research value scores (`research/fingerprinting/notes/04`) for the
 * original probes; the tier-2 hardware probes added in v3 carry nominal weights that have
 * not been measured.
 */
final class ConfidenceScorer
{
    /**
     * @var array<string, array{weight: int, charge: float}>
     */
    private const WEIGHTS = [
        // Tier 1 — synchronous, runs on every load.
        'tier1:environment' => ['weight' => 1100, 'charge' => 1.0],
        'tier1:dateParsing' => ['weight' => 1014, 'charge' => 1.0],
        'tier1:codecs' => ['weight' => 617, 'charge' => 1.0],
        'tier1:cssMedia' => ['weight' => 606, 'charge' => 1.0],
        'tier1:esFeatures' => ['weight' => 524, 'charge' => 1.0],
        'tier1:uaClientHints' => ['weight' => 397, 'charge' => 1.0],
        'tier1:architecture' => ['weight' => 200, 'charge' => 1.0],
        // Engine-identity marks (error-object shape, stack format). Nominal weight: the
        // probe exists for the `ua_vs_engine` cross-check, not for coverage, and it
        // never fails on a real engine, so its weight only has to make "the collector
        // did not send it" visible in `missing`.
        'tier1:engineIdentity' => ['weight' => 100, 'charge' => 1.0],
        // Own-property counts and removed-API boundary: engine facts the collector sends on
        // every load (the first also feeds `browser_key`). Nominal weights, unmeasured.
        'tier1:objectShape' => ['weight' => 200, 'charge' => 1.0],
        'tier1:removedApiBoundary' => ['weight' => 200, 'charge' => 1.0],

        // Tier 2 — deferred to idle time.
        'tier2:textMetrics' => ['weight' => 654, 'charge' => 0.25],
        'tier2:audioRealtime' => ['weight' => 574, 'charge' => 0.25],
        'tier2:errorText' => ['weight' => 509, 'charge' => 0.25],
        'tier2:fontFallback' => ['weight' => 422, 'charge' => 0.25],
        'tier2:intl' => ['weight' => 259, 'charge' => 0.25],
        'tier2:permissions' => ['weight' => 224, 'charge' => 0.25],
        'tier2:audioOffline' => ['weight' => 146, 'charge' => 0.25],
        'tier2:heapMemory' => ['weight' => 120, 'charge' => 0.25],
        // The worker-realm snapshot and the audio read-back invariant, both consistency
        // inputs for server rules (`worker_vs_window_*`, `audio_readback_perturbed`).
        // Nominal weights, unmeasured; `unavailable` (no Worker, blocked, timed out) earns
        // the usual half credit because a browser that cannot run a worker has answered.
        'tier2:workerScope' => ['weight' => 300, 'charge' => 0.25],
        'tier2:audioReadback' => ['weight' => 100, 'charge' => 0.25],
        // Contract 2 probes (nominal, unmeasured). `parallelism` is off by default in the
        // registry and therefore excused from coverage by the policy, not by a low weight.
        'tier2:timezoneLmt' => ['weight' => 100, 'charge' => 0.25],
        'tier2:fontFaces' => ['weight' => 200, 'charge' => 0.25],
        'tier2:parallelism' => ['weight' => 100, 'charge' => 0.25],
        'tier2:gpuMath' => ['weight' => 100, 'charge' => 0.25],
        // The ICU/tzdata build sizes (an engine build fact; moved from tier 1 in the collector).
        'tier2:buildFingerprint' => ['weight' => 100, 'charge' => 0.25],
        // Default-disabled in the registry like `parallelism`: excused by the policy, so the
        // weight only matters to an operator who switches it on.
        'tier2:keyboardLayout' => ['weight' => 50, 'charge' => 0.25],
        // Merged in with probe set 3. Nominal, unmeasured. `behavior` is `unavailable` for a
        // visitor who has not touched the page yet, which is common and honest, so it is
        // weighted low enough that this never moves the coverage number by more than ~1 point;
        // `webrtc` is `unavailable` where WebRTC is disabled (Tor, some privacy settings).
        'tier2:webrtc' => ['weight' => 150, 'charge' => 0.25],
        'tier2:behavior' => ['weight' => 100, 'charge' => 0.25],
        // Probe set 5: private-browsing evidence for the server's soft private-mode signal. Nominal,
        // unmeasured; `unavailable` (no StorageManager, as in some embedded views) earns half credit.
        'tier2:storageProfile' => ['weight' => 50, 'charge' => 0.25],

        // Tier 2 — hardware probes (v3). Nominal weights, unmeasured.
        'tier2:fontMetrics' => ['weight' => 700, 'charge' => 0.25],
        'tier2:gpu' => ['weight' => 500, 'charge' => 0.25],
        'tier2:audioHardware' => ['weight' => 300, 'charge' => 0.25],
        'tier2:scripts' => ['weight' => 200, 'charge' => 0.25],
        'tier2:voices' => ['weight' => 200, 'charge' => 0.25],
        'tier2:emojiMetrics' => ['weight' => 150, 'charge' => 0.25],
        'tier2:decoders' => ['weight' => 150, 'charge' => 0.25],
    ];

    /**
     * The probe catalogue: the shipped `WEIGHTS`, or the host's own list.
     *
     * The shipped list is exactly the probe set of the one collector in this package
     * (`tests/Unit/ProbeSetTest` keeps the two equal), so a host needs no override. The
     * override stays for a host that ships a modified collector or wants other weights:
     * it supplies its catalogue in `fingerprint.confidence_probes` (`'tier:probe' => ['weight' => int, 'charge' => float]`),
     * which REPLACES the shipped list. Malformed entries are skipped; an empty or absent
     * setting keeps the shipped list.
     *
     * @return array<string, array{weight: int, charge: float}>
     */
    public static function catalogue(): array
    {
        $configured = Config::array('fingerprint.confidence_probes');
        $catalogue = [];

        foreach ($configured as $key => $spec) {
            if (! is_string($key) || preg_match('/^tier[12]:[A-Za-z0-9_]+$/', $key) !== 1 || ! is_array($spec)) {
                continue;
            }

            $weight = $spec['weight'] ?? null;
            $charge = $spec['charge'] ?? null;
            if (! is_numeric($weight) || (int) $weight <= 0 || ! is_numeric($charge)) {
                continue;
            }

            $catalogue[$key] = ['weight' => (int) $weight, 'charge' => max(0.0, min(1.0, (float) $charge))];
        }

        return $catalogue === [] ? self::WEIGHTS : $catalogue;
    }

    public const STATE_OK = 'ok';

    public const STATE_UNAVAILABLE = 'unavailable';

    public const STATE_ABSENT = 'absent';

    private const DECLINED_CREDIT = 0.5;

    private const WEBDRIVER_PENALTY = 25;

    private const INTEGRITY_PENALTY = 5;

    private const MAX_INTEGRITY_PENALTY = 20;

    /** The reason recorded for the integrity penalty, followed by the penalty. */
    public const INTEGRITY_REASON_PREFIX = 'client_integrity_findings:';

    /**
     * @param  array<array-key, mixed>  $claims  a decoded claim set
     * @param  list<string>  $disabledProbes  methods the operator switched off; not expected
     */
    public function score(array $claims, ?TransportIntegrityResult $transport = null, array $disabledProbes = []): Confidence
    {
        [$penalty, $reasons] = $this->penalties($claims);

        return $this->scoreFromStates($this->probeStates($claims), $penalty, $reasons, $disabledProbes);
    }

    /**
     * The score for a probe-state map, so a later envelope (tier 2 of the same visit) can
     * be folded into an earlier one without the earlier claim values.
     *
     * A probe the operator switched off (`$disabledProbes`, by probe name) is not expected:
     * it earns nothing and is charged nothing, and it never appears in `missing`. Otherwise
     * every method experiment would read as a coverage drop on every device, which would
     * make the experiments uninterpretable. Core probes are never in that list
     * (ProbeRegistry filters them), so the tier-1 "did the collector run" gate below still
     * has its full weight to measure against.
     *
     * @param  array<string, string>  $states  `tier:probe` => ok|unavailable|absent
     * @param  list<string>  $reasons
     * @param  list<string>  $disabledProbes
     */
    public function scoreFromStates(array $states, int $penalty, array $reasons, array $disabledProbes = []): Confidence
    {
        $catalogue = self::catalogue();
        $expected = 0;
        $earned = 0;
        $missing = [];
        $disabled = array_fill_keys($disabledProbes, true);

        // The tier-2 discount is a claim about WHY tier 2 is missing (the visitor left
        // before idle time), so it needs evidence that the collector ran: at least half
        // of tier 1 by weight answered. One probe is not "the collector ran".
        $tier1Weight = 0;
        $tier1Earned = 0;
        foreach ($catalogue as $key => $spec) {
            if (! str_starts_with($key, 'tier1:') || isset($disabled[explode(':', $key, 2)[1]])) {
                continue;
            }
            $tier1Weight += $spec['weight'];
            if (($states[$key] ?? self::STATE_ABSENT) === self::STATE_OK) {
                $tier1Earned += $spec['weight'];
            }
        }
        $tier1Ran = $tier1Weight > 0 && $tier1Earned * 2 >= $tier1Weight;

        foreach ($catalogue as $key => $spec) {
            if (isset($disabled[explode(':', $key, 2)[1]])) {
                continue;
            }

            $expected += $spec['weight'];
            $state = $states[$key] ?? self::STATE_ABSENT;

            if ($state === self::STATE_OK) {
                $earned += $spec['weight'];

                continue;
            }

            if ($state === self::STATE_UNAVAILABLE) {
                $earned += (int) round($spec['weight'] * self::DECLINED_CREDIT);

                continue;
            }

            $missing[] = $key;

            $charge = ($spec['charge'] < 1.0 && $tier1Ran) ? $spec['charge'] : 1.0;
            $earned += (int) round($spec['weight'] * (1.0 - $charge));
        }

        $ratio = $earned / $expected;
        $score = (int) round(max(0.0, min(1.0, $ratio)) * 100) - max(0, $penalty);

        return new Confidence(
            max(Confidence::MINIMUM, min(Confidence::MAXIMUM, $score)),
            $earned,
            $expected,
            $missing,
            $reasons,
        );
    }

    /**
     * The state of every weighted probe in a claim set.
     *
     * @param  array<array-key, mixed>  $claims
     * @return array<string, string>
     */
    public function probeStates(array $claims): array
    {
        $states = [];
        foreach (array_keys(self::catalogue()) as $key) {
            [$tier, $probe] = explode(':', $key, 2);
            $states[$key] = $this->probeState($claims, $tier, $probe);
        }

        return $states;
    }

    /**
     * Stored states plus a later envelope's: a probe that answered later is `ok`; a known
     * state is never downgraded to absent.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  array<string, string>  $fresh
     * @return array<string, string>
     */
    public static function mergeStates(array $stored, array $fresh): array
    {
        $rank = [self::STATE_ABSENT => 0, self::STATE_UNAVAILABLE => 1, self::STATE_OK => 2];
        $out = [];

        foreach (array_keys(self::catalogue()) as $key) {
            $previous = $stored[$key] ?? self::STATE_ABSENT;
            $previous = is_string($previous) && isset($rank[$previous]) ? $previous : self::STATE_ABSENT;
            $next = $fresh[$key] ?? self::STATE_ABSENT;

            $out[$key] = $rank[$next] >= $rank[$previous] ? $next : $previous;
        }

        return $out;
    }

    /**
     * @param  array<array-key, mixed>  $claims
     */
    private function probeState(array $claims, string $tier, string $probe): string
    {
        $signals = $claims[$tier] ?? null;

        if (! is_array($signals) || ! array_key_exists($probe, $signals)) {
            return self::STATE_ABSENT;
        }

        return $this->nodeState($signals[$probe]);
    }

    /**
     * Classify one probe node. The client sends the raw value when the probe succeeded
     * (a string, number, bool or object) and `{state: 'unavailable'|'error', …}` when it
     * did not (ProbeEnvelope), so any non-null, non-failed value is an answer.
     */
    private function nodeState(mixed $node): string
    {
        if ($node === null) {
            return self::STATE_ABSENT;
        }

        return ProbeEnvelope::isFailed($node) ? self::STATE_UNAVAILABLE : self::STATE_OK;
    }

    /**
     * @param  array<array-key, mixed>  $claims
     * @return array{0: int, 1: list<string>}
     */
    public function penalties(array $claims): array
    {
        $total = 0;
        $reasons = [];

        if ($this->value($claims, 'tier1', 'environment', 'identity', 'webdriver') === true) {
            $total += self::WEBDRIVER_PENALTY;
            $reasons[] = 'webdriver';
        }

        $penalty = $this->integrityPenalty($claims);
        if ($penalty > 0) {
            $total += $penalty;
            $reasons[] = self::INTEGRITY_REASON_PREFIX.$penalty;
        }

        return [$total, $reasons];
    }

    /**
     * The confidence penalty for integrity evidence against this client: see
     * `integrityCount()`, capped at MAX_INTEGRITY_PENALTY.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  list<string>  $alreadyCounted  codes an earlier envelope of the same visit already paid for
     */
    public function integrityPenalty(array $claims, array $alreadyCounted = []): int
    {
        return self::integrityPenaltyFor(self::integrityCount($claims, $alreadyCounted));
    }

    /**
     * The penalty for a count of integrity findings, capped at MAX_INTEGRITY_PENALTY. Public
     * so a visit's two envelopes can be capped TOGETHER (`FingerprintIngest` tier 2): capping
     * each envelope on its own let one visit pay twice the cap.
     */
    public static function integrityPenaltyFor(int $count): int
    {
        return min(self::MAX_INTEGRITY_PENALTY, max(0, $count) * self::INTEGRITY_PENALTY);
    }

    /**
     * How many integrity findings count against this client: every finding entry the client
     * reported (one per occurrence, as the client counts them, unchanged), plus one per code
     * the server derived from the client's own integrity data that the client did NOT report
     * (`IntegrityFindings`, notes/24 F10). Without the second term, sending the tell-tale data
     * with an empty findings list avoided the penalty.
     *
     * `$alreadyCounted` keeps one fact from being charged twice in one visit: the tier-2
     * envelope carries a re-measure of `canvasFill` that the client reports only in the first
     * phase, so a server-derived code the tier-1 envelope already paid for is not counted
     * again. The caller passes the effective codes tier 1 stored (`probe_states.integrity_codes`),
     * which do not depend on rule weights: a rule weighted 0 is absent from the disagreements,
     * and reading the codes from there counted the fact twice (round 4, BE-F1/SK-4).
     *
     * @param  array<array-key, mixed>  $claims
     * @param  list<string>  $alreadyCounted
     */
    public static function integrityCount(array $claims, array $alreadyCounted = []): int
    {
        $integrity = $claims['integrity'] ?? null;
        $findings = is_array($integrity) ? ($integrity['findings'] ?? null) : null;
        $count = is_array($findings) ? count($findings) : 0;
        $skip = array_fill_keys($alreadyCounted, true);

        foreach (IntegrityFindings::effective($claims) as $code => $provenance) {
            if ($provenance === IntegrityFindings::PROVENANCE_SERVER && ! isset($skip[$code])) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * A claim value through the probe envelope (ProbeEnvelope, via the engine's one reader).
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function value(array $claims, string ...$path): mixed
    {
        return EnvironmentConsistency::read($claims, ...$path);
    }
}

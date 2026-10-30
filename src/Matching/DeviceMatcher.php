<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Matching;

use NutriCompare\Fingerprint\Keys\DeviceComponents;
use NutriCompare\Fingerprint\Keys\DeviceKeys;

/**
 * Finds the device a claim set most probably belongs to.
 *
 * 0. A PROTECTED key set (Firefox resistFingerprinting or Tor Browser under the engine
 *    evidence gate, `DeviceKeys::$protected`; largely client-reported, see
 *    `EnvironmentConsistency::engineEvidence()`) is not matched at all: it is a new device,
 *    `MatchResult::protectedNew()`. Those browsers report the same tier-1 constants
 *    (letterboxed screen, spoofed cores, UTC, en-US), so two different people with the same
 *    window bucket and version derive one `browser_key`; linking on it would make them one
 *    device (block one, block all) and let a fraudster hide inside an honest cohort
 *    (anti-fraud review). Their hard components are already absent (`untrusted()`), so the
 *    scored stage would have no candidates either. The same browser profile is still
 *    recognised by its own cookie (`DeviceIdentityResolver`), which is per profile, not per
 *    cohort. The sources never return a protected ROW as a candidate or an exact match.
 * 1. Exact `browser_key` equality — the row's own key or a key the `device_browser_keys`
 *    link table records for its cluster (G-D3i) — is the legacy exact-hash identity. It is
 *    FINAL (posterior 1.0) only from the candidate's own network (`matchNetwork()`); from any
 *    other network it is PROVISIONAL (`MatchResult::$provisional`, posterior below the link
 *    threshold), and only a later report FROM THE CANDIDATE'S NETWORK promotes it — never
 *    the client's components alone (round-3 R3-S2: since G-D3i the browser key is a class key,
 *    and the high-entropy components are client-asserted values a whole GPU generation or
 *    OS image shares).
 * 2. Otherwise candidates are devices seen inside the window whose `hardware_key` equals
 *    ours, or whose `block_tuple` (sha256 of os|arch|touch, G-D2i) does — two index-backed
 *    lookups. One row per CLUSTER is scored (the newest), so a device's own earlier linked
 *    rows never tie with their root. Each is scored: +weight per agreeing soft component,
 *    -weight per soft component present on both and disagreeing, +weight when the browser
 *    keys are equal and +weight when the hardware keys are equal (neither is ever a
 *    penalty when they differ: a browser switch is the case this exists for). The
 *    posterior is `logistic((score - midpoint) / scale)`.
 * 3. posterior >= link, untied, with a high-entropy agreement and no high-entropy
 *    disagreement                                            -> LINK to that device
 *    posterior >= link otherwise, or posterior >= possible -> `possible`: a new device,
 *    `linked_device_id` + `link_posterior` recorded (`linkVeto` says why a link-level
 *    score was demoted)
 *    else                                                     -> new device
 *
 *    The high-entropy rule exists because the class components alone reach the link
 *    threshold (round-2 skeptical §3.1: a different machine with the same OS image and a
 *    different GPU linked at 0.92): a link additionally needs fonts (Jaccard at or above
 *    `fonts_agree_jaccard`), the gpu class (WebGPU vendor/architecture, or the same
 *    engine's WebGL class) or the OS voice set (non-empty) to agree, and none of fonts,
 *    the same-engine gpu class or the panel to disagree.
 *
 * Weights and thresholds come from {@see MatcherSettings::current()} (`fingerprint.matcher`
 * through `Config`; the application answers it from its settings store). The rows come from
 * the `DeviceCandidateSource` the host passes: in the application `fingerprint_devices`
 * (the container's default binding) and `visitor_devices` for the `nc_vid` identity
 * (DeviceIdentityResolver), with this one scoring for both. The package has no storage, so
 * the source is a required argument rather than a default.
 *
 * `tiedAtBest` on the result counts the clusters that share the best score. A tie never
 * links (G-D1i: two identical machines behind one network are two devices).
 */
final class DeviceMatcher
{
    /** Scripts (box-glyph bits): agree at a Hamming distance up to this. */
    private const SCRIPTS_AGREE_DISTANCE = 1;

    /** Scripts: disagree above this distance; between the two is neutral (round-2 BR2-5). */
    private const SCRIPTS_NEUTRAL_DISTANCE = 6;

    public function __construct(private readonly DeviceCandidateSource $source) {}

    public function source(): DeviceCandidateSource
    {
        return $this->source;
    }

    /**
     * @param  int|null  $excludeDeviceId  the observation's current device, when re-matching at tier 2
     * @param  string|null  $network  the request's same-network token, of the kind the source's
     *                                rows carry (`MatchCandidate::matchNetwork()`): an exact
     *                                browser-key match is final only when the two are equal
     */
    public function match(DeviceKeys $keys, ?int $organizationId, ?int $excludeDeviceId = null, ?string $network = null): MatchResult
    {
        if ($keys->protected) {
            return MatchResult::protectedNew($keys->coverage);
        }

        $settings = MatcherSettings::current();

        if ($keys->browserKey !== null) {
            $exact = $this->source->exact($keys->browserKey, $keys->saltVersion, $organizationId, $excludeDeviceId, $settings['window_days'], $network);

            if ($exact !== null) {
                // Since G-D3i the browser key is a CLASS key (engine build family, OS, screen,
                // codecs): every unit of one phone model on one OS release and browser major
                // shares it. The match is FINAL only from the candidate's own network
                // (`matchNetwork()`: the keyed /24 or /56 `link_network` in both stores);
                // from any other network it is PROVISIONAL — a link
                // below the threshold — whatever the client's components say (round-3 R3-S2:
                // the high-entropy components are client-asserted and shared by a whole GPU
                // generation or OS image, so ten strangers on ten networks used to link FINAL
                // on one agreeing value). The veto is still computed: it is the logged reason.
                $veto = $this->linkVeto($keys, $exact, 1, $settings);
                $sameNetwork = $network !== null && $exact->matchNetwork() === $network;
                $posterior = $sameNetwork ? 1.0 : MatchResult::provisionalPosterior($settings);
                $veto ??= MatchResult::VETO_OTHER_NETWORK;

                return new MatchResult(
                    $exact->matchId(),
                    $posterior,
                    MatchResult::confidenceFor($keys->coverage, $posterior),
                    MatchResult::METHOD_BROWSER_KEY,
                    null,
                    1,
                    1,
                    false,
                    $exact->matchClusterId(),
                    $posterior < 1.0 ? $veto : null,
                    $posterior < 1.0,
                );
            }
        }

        $candidates = $this->candidates($keys, $organizationId, $excludeDeviceId, $settings);

        $best = null;
        $bestScore = PHP_INT_MIN;
        $tied = 0;

        // Ties are counted on the integer score, not the posterior: the logistic
        // saturates, so two strong candidates scoring 14 and 12 both round to 1.0.
        foreach ($candidates as $candidate) {
            $score = $this->score($keys, $candidate, $settings['weights'], $settings);

            if ($best === null || $score > $bestScore) {
                $best = $candidate;
                $bestScore = $score;
                $tied = 1;
            } elseif ($score === $bestScore) {
                $tied++;
            }
        }

        $bestPosterior = $best === null ? 0.0 : $this->posterior($bestScore, $settings['midpoint'], $settings['scale']);

        $confidence = MatchResult::confidenceFor($keys->coverage, $bestPosterior);
        $considered = count($candidates);
        $tied = max(1, $tied);

        if ($best !== null && $bestPosterior >= $settings['link_posterior']) {
            $veto = $this->linkVeto($keys, $best, $tied, $settings);

            if ($veto === null) {
                return new MatchResult($best->matchId(), $bestPosterior, $confidence, MatchResult::METHOD_HARDWARE, null, $considered, $tied, false, $best->matchClusterId());
            }

            return new MatchResult(null, $bestPosterior, $confidence, MatchResult::METHOD_POSSIBLE, $best->matchId(), $considered, $tied, false, $best->matchClusterId(), $veto);
        }

        if ($best !== null && $bestPosterior >= $settings['possible_posterior']) {
            return new MatchResult(null, $bestPosterior, $confidence, MatchResult::METHOD_POSSIBLE, $best->matchId(), $considered, $tied, false, $best->matchClusterId());
        }

        return new MatchResult(null, $bestPosterior, $confidence, MatchResult::METHOD_NEW, null, $considered, $tied);
    }

    /**
     * Why a link-level posterior must not become a link, or null when it may.
     *
     * @param  array{weights: array<string, int>, fonts_agree_jaccard: float, fonts_disagree_jaccard: float, link_requires_high_entropy_agreement: bool, high_entropy_components: list<string>, veto_components: list<string>}  $settings
     */
    private function linkVeto(DeviceKeys $keys, MatchCandidate $candidate, int $tied, array $settings): ?string
    {
        if ($tied > 1) {
            return MatchResult::VETO_TIED;
        }

        $theirs = $candidate->matchComponents();

        foreach ($settings['veto_components'] as $name) {
            if ($this->componentAgreement($name, $keys->components, $theirs, $settings) === false) {
                return MatchResult::VETO_HIGH_ENTROPY_DISAGREEMENT;
            }
        }

        if (! $settings['link_requires_high_entropy_agreement']) {
            return null;
        }

        foreach ($settings['high_entropy_components'] as $name) {
            if ($this->componentAgreement($name, $keys->components, $theirs, $settings) === true) {
                return null;
            }
        }

        return MatchResult::VETO_NO_HIGH_ENTROPY_AGREEMENT;
    }

    /**
     * Whether one named component agrees between two component maps: true, false, or null
     * when either side lacks it or the comparison says nothing.
     *
     * @param  array<string, scalar|null>  $mine
     * @param  array<string, scalar|null>  $theirs
     * @param  array{fonts_agree_jaccard: float, fonts_disagree_jaccard: float}  $settings
     */
    private function componentAgreement(string $name, array $mine, array $theirs, array $settings): ?bool
    {
        $a = $mine[$name] ?? null;
        $b = $theirs[$name] ?? null;

        if ($a === null || $b === null || ! is_scalar($a) || ! is_scalar($b)) {
            return null;
        }

        return $this->agreement($name, (string) $a, (string) $b, $settings, DeviceComponents::engineOf($mine), DeviceComponents::engineOf($theirs));
    }

    /**
     * The soft-component agreement score for one candidate.
     *
     * @param  array<string, int>  $weights
     * @param  array{fonts_agree_jaccard: float, fonts_disagree_jaccard: float}|null  $settings  the matcher settings; read when null
     */
    public function score(DeviceKeys $keys, MatchCandidate $candidate, array $weights, ?array $settings = null): int
    {
        $settings ??= MatcherSettings::current();
        $theirs = $candidate->matchComponents();
        $myEngine = DeviceComponents::engineOf($keys->components);
        $theirEngine = DeviceComponents::engineOf($theirs);
        $score = 0;
        $gpuDecided = false;

        foreach (DeviceComponents::SOFT as $name) {
            $weight = $weights[$name] ?? 0;
            if ($weight <= 0) {
                continue;
            }

            $mine = $keys->components[$name] ?? null;
            $other = $theirs[$name] ?? null;

            if ($mine === null || $other === null || ! is_scalar($other)) {
                continue;
            }

            $agreement = $this->agreement($name, (string) $mine, (string) $other, $settings, $myEngine, $theirEngine);

            // `gpuMath` (notes/22 M1) exists for the case `gpu` cannot decide — two engines'
            // WebGL classes are incomparable — so it is consulted only then, and it is
            // agree-only: a driver or browser update changes the shader compiler, and a
            // lost agreement must not become a penalty. `gpu` precedes it in SOFT.
            if ($name === 'gpuMath' && ($gpuDecided || $agreement !== true)) {
                continue;
            }

            if ($agreement === null) {
                continue;
            }

            if ($name === 'gpu') {
                $gpuDecided = true;
            }

            $score += $agreement ? $weight : -$weight;
        }

        $theirBrowserKey = $candidate->matchBrowserKey();
        if ($keys->browserKey !== null && $theirBrowserKey !== null && hash_equals($theirBrowserKey, $keys->browserKey)) {
            $score += $weights['browser_key'] ?? 0;
        }

        $theirHardwareKey = $candidate->matchHardwareKey();
        if ($keys->hardwareKey !== null && $theirHardwareKey !== null && hash_equals($theirHardwareKey, $keys->hardwareKey)) {
            $score += $weights['hardware_key'] ?? 0;
        }

        return $score;
    }

    /**
     * Whether two values of one soft component agree (true), disagree (false) or say
     * nothing (null, scored as absent).
     *
     * - `cores`: neutral when either side is WebKit — Safari caps `hardwareConcurrency`,
     *   so Safari and Chrome on one Mac disagree by construction (round-2 BR2-3 / STD-27).
     * - `scripts`: a Hamming distance of at most 1 agrees (one bit differs across engines
     *   by font-fallback policy, and Firefox flips one bit cold vs warm), 2..6 says
     *   nothing (Firefox ETP-strict/private differ by 6, measured), above 6 disagrees.
     * - `gpu`: a WebGL class (`webgl:<engine>:<hash>`) is engine-conditioned, so two
     *   classes from different engines are neutral; WebGPU `vendor/architecture` compares
     *   across engines.
     * - `fonts`: Jaccard of the keyed pair-token sets; at or above `fonts_agree_jaccard`
     *   agrees, below `fonts_disagree_jaccard` disagrees, in between is neutral.
     *   Cross-engine Jaccard on one Linux machine measured 0.8 (8 of 10 pairs shared;
     *   round-2 R2-10 corrected the "20 %" this comment used to say), i.e. exactly at the
     *   agree boundary — the neutral band below it is what keeps a browser switch from
     *   being penalised.
     *
     * @param  array{fonts_agree_jaccard: float, fonts_disagree_jaccard: float}  $settings
     */
    private function agreement(string $component, string $mine, string $other, array $settings, ?string $myEngine = null, ?string $theirEngine = null): ?bool
    {
        if ($component === 'cores' && ($myEngine === 'webkit' || $theirEngine === 'webkit')) {
            return null;
        }

        if ($component === 'scripts') {
            $distance = DeviceComponents::bitsDistance($mine, $other);

            if ($distance === null) {
                return $mine === $other;
            }

            return match (true) {
                $distance <= self::SCRIPTS_AGREE_DISTANCE => true,
                $distance <= self::SCRIPTS_NEUTRAL_DISTANCE => null,
                default => false,
            };
        }

        if ($component === 'gpu' && str_starts_with($mine, 'webgl:') && str_starts_with($other, 'webgl:')) {
            // `webgl:<engine>:<class>`: classes from different engines say nothing.
            $mineEngine = explode(':', $mine, 3)[1] ?? '';
            $otherEngine = explode(':', $other, 3)[1] ?? '';
            if ($mineEngine !== $otherEngine) {
                return null;
            }
        }

        if ($component === 'fonts') {
            $similarity = DeviceComponents::fontsSimilarity($mine, $other);
            if ($similarity === null) {
                return null;
            }
            if ($similarity >= $settings['fonts_agree_jaccard']) {
                return true;
            }

            return $similarity < $settings['fonts_disagree_jaccard'] ? false : null;
        }

        return $mine === $other;
    }

    public function posterior(int $score, float $midpoint, float $scale): float
    {
        $scale = $scale <= 0.0 ? 1.0 : $scale;

        return round(1.0 / (1.0 + exp(-($score - $midpoint) / $scale)), 4);
    }

    /**
     * The `block_tuple` of a key set (sha256 of os|arch|touch), or null when any of the
     * three is unknown.
     */
    public static function blockingTuple(DeviceKeys $keys): ?string
    {
        return DeviceComponents::blockTuple($keys->components);
    }

    /**
     * One candidate per cluster, newest first: the source returns rows newest first, and a
     * cluster's own earlier linked rows carry the same components as the root, so they
     * would tie with it and demote every return visit to `possible`.
     *
     * @param  array{weights: array<string, int>, link_posterior: float, possible_posterior: float, midpoint: float, scale: float, window_days: int, max_candidates: int, fonts_agree_jaccard: float, fonts_disagree_jaccard: float}  $settings
     * @return list<MatchCandidate>
     */
    private function candidates(DeviceKeys $keys, ?int $organizationId, ?int $excludeDeviceId, array $settings): array
    {
        $tuple = self::blockingTuple($keys);

        if ($keys->hardwareKey === null && $tuple === null) {
            return [];
        }

        $rows = $this->source->candidates(
            $keys->hardwareKey,
            $tuple,
            $keys->saltVersion,
            $organizationId,
            $excludeDeviceId,
            $settings['window_days'],
            $settings['max_candidates'],
        );

        $perCluster = [];
        foreach ($rows as $row) {
            $perCluster[$row->matchClusterId()] ??= $row;
        }

        return array_values($perCluster);
    }
}

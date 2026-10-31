<?php

declare(strict_types=1);

namespace DeviceId\Matching;

use DeviceId\Support\Config;

/**
 * Hand-set matcher policy that comes from published evidence rather than from a host's weight
 * table (arXiv survey, 2026-10-31, section 3b). It is a separate object from
 * {@see MatcherSettings} on purpose: that normalised shape is pinned by the host applications'
 * tests, and these are additive rules, not new members of it.
 *
 * Read from `fingerprint.matcher_policy` through {@see Config}:
 *
 * - `mobile_webkit_link_posterior` (default 0.9): the posterior a MOBILE (touch) or WEBKIT
 *   visit needs to link. Mobile fingerprints are 40 % unique against 66 % on desktop (#11) and
 *   WebKit hides the most entropy, so two iPhones of one model collide on nearly every component.
 *   Never lower than the ordinary link posterior.
 * - `keyboard_independent_of_language` (default false): keyboard layout is not independent of
 *   the language (#10), so by default a keyboard agreement is not counted on top of an agreeing
 *   OS voice set.
 * - `default_weights`: weights used for a component the host did NOT configure at all. An
 *   explicit 0 stays 0 (that is how a host switches a component off). Defaults: `gpuCaps` 3
 *   (static WebGPU/WebGL exposure was 80/80 stable against 57/80 for timing and output
 *   fingerprints, #4) which must outweigh `gpuMath` (an output hash), and `keyboard` 1.
 */
final readonly class MatcherPolicy
{
    /** Components that can raise a match but must never veto one. */
    public const NEVER_VETO = ['gpuMath', 'keyboard', 'gpuCaps', 'codecsHw'];

    public const DEFAULT_MOBILE_WEBKIT_LINK_POSTERIOR = 0.9;

    /**
     * @param  array<string, int>  $defaultWeights
     */
    public function __construct(
        public float $mobileWebkitLinkPosterior = self::DEFAULT_MOBILE_WEBKIT_LINK_POSTERIOR,
        public bool $keyboardIsIndependentOfLanguage = false,
        public array $defaultWeights = ['gpuCaps' => 3, 'keyboard' => 1],
    ) {}

    public static function current(): self
    {
        $configured = Config::array('fingerprint.matcher_policy');
        $defaults = new self;

        $weights = $defaults->defaultWeights;
        foreach (is_array($configured['default_weights'] ?? null) ? $configured['default_weights'] : [] as $name => $weight) {
            if (is_string($name) && is_numeric($weight)) {
                $weights[$name] = max(0, min(60, (int) $weight));
            }
        }

        $posterior = $configured['mobile_webkit_link_posterior'] ?? null;

        return new self(
            is_numeric($posterior) ? max(0.0, min(1.0, (float) $posterior)) : $defaults->mobileWebkitLinkPosterior,
            ($configured['keyboard_independent_of_language'] ?? false) === true,
            $weights,
        );
    }

    /**
     * The configured weights with the policy default laid under every component the host did
     * not mention. `gpuCaps` is also kept strictly above `gpuMath` when the host configured
     * `gpuMath` but not `gpuCaps`.
     *
     * @param  array<string, int>  $weights
     * @return array<string, int>
     */
    public function effectiveWeights(array $weights): array
    {
        $caps = array_key_exists('gpuCaps', $weights) ? null : ($this->defaultWeights['gpuCaps'] ?? null);

        foreach ($this->defaultWeights as $name => $default) {
            if (! array_key_exists($name, $weights)) {
                $weights[$name] = $default;
            }
        }

        // A host that raised `gpuMath` but never mentioned `gpuCaps` must not end up with the
        // output hash outweighing the static capability list.
        if ($caps !== null && isset($weights['gpuMath'])) {
            $weights['gpuCaps'] = max($caps, $weights['gpuMath'] + 1);
        }

        return $weights;
    }

    /**
     * The link posterior for a pair: the stricter one when either side is a touch device or
     * WebKit.
     *
     * @param  array<string, scalar|null>  $mine
     * @param  array<string, scalar|null>  $theirs
     */
    public function linkPosteriorFor(array $mine, array $theirs, float $ordinary): float
    {
        $isMobile = ($mine['touch'] ?? 0) === 1 || ($theirs['touch'] ?? 0) === 1;
        $isWebkit = ($mine['engine'] ?? null) === 'webkit' || ($theirs['engine'] ?? null) === 'webkit';

        return $isMobile || $isWebkit ? max($ordinary, $this->mobileWebkitLinkPosterior) : $ordinary;
    }
}

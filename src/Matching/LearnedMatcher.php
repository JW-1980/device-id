<?php

declare(strict_types=1);

namespace DeviceId\Matching;

use DeviceId\Keys\DeviceComponents;
use DeviceId\Keys\DeviceKeys;
use DeviceId\Support\Config;

/**
 * The learned (Fellegi-Sunter) posterior next to the hand one.
 *
 * Modes (`fingerprint.matcher_learned.mode`): `off`, `shadow` (the learned posterior is
 * computed and returned on the result for logging; the decision is the hand matcher's) and
 * `active` (the learned posterior decides). `active` is honoured only when the weights file
 * passes {@see LearnedWeights::promotion()} - 1,000 pairs in every slice - otherwise the matcher
 * runs in `shadow` and says so in {@see effectiveMode()}.
 */
final class LearnedMatcher
{
    public const MODE_OFF = 'off';

    public const MODE_SHADOW = 'shadow';

    public const MODE_ACTIVE = 'active';

    public function __construct(private readonly MatcherWeightsSource $source, private readonly string $mode = self::MODE_SHADOW, private readonly int $minimumPairsPerSlice = LearnedWeights::MIN_PAIRS_PER_SLICE) {}

    /**
     * From `fingerprint.matcher_learned` ({@see Config}): `mode` and `path`; null when off or
     * not configured.
     */
    public static function fromConfig(): ?self
    {
        $block = Config::array('fingerprint.matcher_learned');
        $mode = $block['mode'] ?? self::MODE_OFF;
        $path = $block['path'] ?? null;

        if (! in_array($mode, [self::MODE_SHADOW, self::MODE_ACTIVE], true) || ! is_string($path) || $path === '') {
            return null;
        }

        return new self(new JsonFileMatcherWeightsSource($path), $mode);
    }

    public function effectiveMode(): string
    {
        if ($this->mode === self::MODE_ACTIVE) {
            $weights = $this->source->load();

            return $weights !== null && $weights->promotion($this->minimumPairsPerSlice)['promotable'] ? self::MODE_ACTIVE : self::MODE_SHADOW;
        }

        return $this->mode === self::MODE_SHADOW ? self::MODE_SHADOW : self::MODE_OFF;
    }

    /**
     * The learned posterior for one candidate, or null when there are no usable weights.
     */
    public function posterior(DeviceMatcher $matcher, DeviceKeys $keys, MatchCandidate $candidate, array $settings): ?float
    {
        $weights = $this->source->load();
        if ($weights === null) {
            return null;
        }

        return $weights->posterior(self::comparisons($matcher, $keys, $candidate, $settings));
    }

    /**
     * The comparison map the learned weights are applied to and estimated from: every soft
     * component (weight-independent) plus `browser_key` and `hardware_key` when equal.
     *
     * @param  array{fonts_agree_jaccard: float, fonts_disagree_jaccard: float}  $settings
     * @return array<string, bool>
     */
    public static function comparisons(DeviceMatcher $matcher, DeviceKeys $keys, MatchCandidate $candidate, array $settings): array
    {
        $comparisons = $matcher->comparisons($keys, $candidate, array_fill_keys(DeviceComponents::SOFT, 1), $settings);

        $theirBrowser = $candidate->matchBrowserKey();
        if ($keys->browserKey !== null && $theirBrowser !== null) {
            $comparisons['browser_key'] = hash_equals($theirBrowser, $keys->browserKey);
        }
        $theirHardware = $candidate->matchHardwareKey();
        if ($keys->hardwareKey !== null && $theirHardware !== null) {
            $comparisons['hardware_key'] = hash_equals($theirHardware, $keys->hardwareKey);
        }

        return $comparisons;
    }
}

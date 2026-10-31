<?php

declare(strict_types=1);

namespace DeviceId\Matching;

use DeviceId\Keys\DeviceComponents;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\Config;

/**
 * The matcher's weights and thresholds ({@see DeviceMatcher}), normalised: one function from
 * whatever a host configured to the exact shape the matcher reads, with the shipped defaults,
 * the clamps and the component-name filter applied.
 *
 * ## Why this is a class of its own (2026-10-21, one-engine migration)
 *
 * The normalisation used to live in the Laravel application's settings store, so a host
 * without that store had no way to arrive at the same defaults. It lives here now, and the
 * application's store calls THIS function with its stored overrides, so a plain-PHP host
 * passing `fingerprint.matcher` through `Config` and the application agree on every default
 * and every clamp by construction rather than by a copy.
 *
 * Normalising an already-normalised array returns it unchanged (pinned by a unit test). That
 * is what lets the application's `Config` resolver hand the engine the store's normalised
 * array and the matcher normalise it again without a difference.
 *
 * @phpstan-type Normalised array{weights: array<string, int>, link_posterior: float, possible_posterior: float, midpoint: float, scale: float, link_requires_high_entropy_agreement: bool, high_entropy_components: list<string>, veto_components: list<string>, max_cluster_members: int, window_days: int, max_candidates: int, fonts_agree_jaccard: float, fonts_disagree_jaccard: float}
 */
final class MatcherSettings
{
    /**
     * The settings the engine runs with: `fingerprint.matcher` from {@see Config}, normalised.
     *
     * @return Normalised
     */
    public static function current(): array
    {
        return self::fromConfig(Config::array('fingerprint.matcher'));
    }

    /**
     * Normalise a configured matcher block, with optional stored weight OVERRIDES on top.
     *
     * The shipped weight table comes first and the overrides are laid over it, only for
     * components the table knows (round-2 BE2-14: a stored snapshot that REPLACED the table
     * made a component added in a later release weigh 0 on every deployment that had ever
     * saved the screen). Every weight is clamped to 0..{@see EnvironmentConsistency::MAX_WEIGHT};
     * every threshold to its range, falling back to the default when absent or not numeric.
     *
     * @param  array<array-key, mixed>  $configured  the `matcher` block (e.g. `config/security.php`)
     * @param  mixed  $storedWeights  a host's stored weight overrides (component => weight), or null;
     *                                anything that is not an array is ignored
     * @return Normalised
     */
    public static function fromConfig(array $configured, mixed $storedWeights = null): array
    {
        $weights = [];
        foreach (is_array($configured['weights'] ?? null) ? $configured['weights'] : [] as $component => $weight) {
            if (is_string($component) && is_numeric($weight)) {
                $weights[$component] = max(0, min(EnvironmentConsistency::MAX_WEIGHT, (int) $weight));
            }
        }
        foreach (is_array($storedWeights) ? $storedWeights : [] as $component => $weight) {
            if (is_string($component) && is_numeric($weight) && array_key_exists($component, $weights)) {
                $weights[$component] = max(0, min(EnvironmentConsistency::MAX_WEIGHT, (int) $weight));
            }
        }

        $float = static function (string $key, float $default, float $min, float $max) use ($configured): float {
            $value = $configured[$key] ?? null;

            return is_numeric($value) ? max($min, min($max, (float) $value)) : $default;
        };
        $int = static function (string $key, int $default, int $min, int $max) use ($configured): int {
            $value = $configured[$key] ?? null;

            return is_numeric($value) ? max($min, min($max, (int) $value)) : $default;
        };

        $possible = $float('possible_posterior', 0.5, 0.0, 1.0);
        $link = max($possible, $float('link_posterior', 0.8, 0.0, 1.0));

        return [
            'weights' => $weights,
            'link_posterior' => $link,
            'possible_posterior' => $possible,
            'midpoint' => $float('midpoint', 3.0, -100.0, 100.0),
            'scale' => $float('scale', 1.5, 0.01, 100.0),
            // A link needs one of these to agree and none of the veto set to disagree
            // (DeviceMatcher::linkVeto; the class components alone reach the threshold).
            'link_requires_high_entropy_agreement' => ($configured['link_requires_high_entropy_agreement'] ?? true) !== false,
            'high_entropy_components' => self::componentNames($configured, 'high_entropy_components', ['fonts', 'gpu', 'voices']),
            'veto_components' => self::componentNames($configured, 'veto_components', ['fonts', 'gpu', 'panel']),
            // A cluster root with this many linked members accepts no further link
            // (`possible` instead): the valve against a popular device class collapsing
            // into one cluster (round-2 FR2-1).
            'max_cluster_members' => $int('max_cluster_members', 8, 1, 10000),
            'window_days' => $int('window_days', 90, 1, 3650),
            'max_candidates' => $int('max_candidates', 200, 1, 2000),
            'fonts_agree_jaccard' => $float('fonts_agree_jaccard', 0.8, 0.0, 1.0),
            'fonts_disagree_jaccard' => $float('fonts_disagree_jaccard', 0.3, 0.0, 1.0),
        ];
    }

    /**
     * A configured list of soft component names, or the default when the setting is
     * absent or not a list; unknown names are dropped.
     *
     * @param  array<array-key, mixed>  $configured
     * @param  list<string>  $default
     * @return list<string>
     */
    private static function componentNames(array $configured, string $key, array $default): array
    {
        $value = $configured[$key] ?? null;
        if (! is_array($value)) {
            return $default;
        }

        $out = [];
        foreach ($value as $name) {
            if (is_string($name) && in_array($name, DeviceComponents::SOFT, true)) {
                $out[] = $name;
            }
        }

        return $out;
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Matching;

/**
 * Fellegi-Sunter m/u estimation by expectation-maximisation, in pure PHP.
 *
 * Each pair is a map component => agrees (true) / disagrees (false); a component that said
 * nothing is absent and contributes no weight. Components are assumed conditionally independent
 * given match status (the classical model; the correlated ones - keyboard and language - are
 * handled by {@see DeviceMatcher::comparisons()}, not here).
 *
 * - `m`: P(outcome | same device); `u`: P(outcome | different devices).
 * - agree weight = log2(m_agree / u_agree); disagree weight = log2(m_disagree / u_disagree).
 *   They are NOT mirror images: that is the point of estimating them.
 *
 * ## Labels
 *
 * A pair may carry a known label (`true` same, `false` different, `null` unknown). Known pairs
 * keep a fixed responsibility; unknown ones are re-estimated each round. Fully unlabelled EM
 * works but is only identifiable when the match class is separable, so a host should label
 * what it can (same account + same cookie = same device) and feed the rest as unknown.
 *
 * ## What this cannot do
 *
 * `u` is the agreement rate of strangers and needs a population of different-device pairs. The
 * capture harness is one machine, so locally only `m` is measurable; the estimator refuses to
 * return weights when either class has fewer than {@see MIN_CLASS_PAIRS} effective pairs.
 */
final class FellegiSunter
{
    public const MIN_CLASS_PAIRS = 5.0;

    /**
     * @param  list<array{c: array<string, bool>, slice?: string, same?: bool|null}>  $pairs
     * @param  list<string>|null  $components  default: every component seen
     */
    public static function estimate(array $pairs, ?array $components = null, int $iterations = 100, float $smoothing = 0.5, array $metadata = []): ?LearnedWeights
    {
        if ($pairs === []) {
            return null;
        }

        if ($components === null) {
            $seen = [];
            foreach ($pairs as $pair) {
                foreach ($pair['c'] as $name => $_) {
                    $seen[$name] = true;
                }
            }
            $components = array_keys($seen);
            sort($components);
        }

        $n = count($pairs);
        $responsibility = [];
        foreach ($pairs as $i => $pair) {
            $known = $pair['same'] ?? null;
            if ($known !== null) {
                $responsibility[$i] = $known ? 1.0 : 0.0;
            } else {
                $agree = count(array_filter($pair['c'], static fn (bool $a): bool => $a));
                $total = max(1, count($pair['c']));
                $responsibility[$i] = $agree / $total >= 0.5 ? 0.9 : 0.1;
            }
        }

        $m = $u = [];
        $prior = 0.5;
        for ($round = 0; $round < $iterations; $round++) {
            $sumM = array_sum($responsibility);
            $sumU = $n - $sumM;
            if ($sumM < self::MIN_CLASS_PAIRS || $sumU < self::MIN_CLASS_PAIRS) {
                return null;
            }
            $prior = $sumM / $n;

            foreach ($components as $component) {
                $cm = ['a' => $smoothing, 'd' => $smoothing, 'x' => $smoothing];
                $cu = ['a' => $smoothing, 'd' => $smoothing, 'x' => $smoothing];
                foreach ($pairs as $i => $pair) {
                    $outcome = isset($pair['c'][$component]) ? ($pair['c'][$component] ? 'a' : 'd') : 'x';
                    $cm[$outcome] += $responsibility[$i];
                    $cu[$outcome] += 1.0 - $responsibility[$i];
                }
                $totalM = array_sum($cm);
                $totalU = array_sum($cu);
                $m[$component] = array_map(static fn (float $v): float => $v / $totalM, $cm);
                $u[$component] = array_map(static fn (float $v): float => $v / $totalU, $cu);
            }

            $moved = 0.0;
            foreach ($pairs as $i => $pair) {
                if (($pair['same'] ?? null) !== null) {
                    continue;
                }
                $logit = log($prior / (1.0 - $prior));
                foreach ($components as $component) {
                    $outcome = isset($pair['c'][$component]) ? ($pair['c'][$component] ? 'a' : 'd') : 'x';
                    $logit += log($m[$component][$outcome] / $u[$component][$outcome]);
                }
                $next = 1.0 / (1.0 + exp(-max(-30.0, min(30.0, $logit))));
                $moved = max($moved, abs($next - $responsibility[$i]));
                $responsibility[$i] = $next;
            }
            if ($moved < 1e-9) {
                break;
            }
        }

        $weights = [];
        foreach ($components as $component) {
            $count = 0;
            foreach ($pairs as $pair) {
                $count += isset($pair['c'][$component]) ? 1 : 0;
            }
            $weights[$component] = [
                'agree' => round(log($m[$component]['a'] / $u[$component]['a'], 2), 6),
                'disagree' => round(log($m[$component]['d'] / $u[$component]['d'], 2), 6),
                'm_agree' => round($m[$component]['a'], 6),
                'u_agree' => round($u[$component]['a'], 6),
                'm_disagree' => round($m[$component]['d'], 6),
                'u_disagree' => round($u[$component]['d'], 6),
                'n' => $count,
            ];
        }

        $slices = [];
        foreach ($pairs as $pair) {
            $slice = $pair['slice'] ?? 'all';
            $slices[$slice] = ($slices[$slice] ?? 0) + 1;
        }
        ksort($slices);

        return new LearnedWeights($weights, round(log($prior / (1.0 - $prior)), 6), $slices, $metadata + ['pairs' => $n, 'iterations' => $iterations, 'smoothing' => $smoothing]);
    }
}

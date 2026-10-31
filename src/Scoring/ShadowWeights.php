<?php

declare(strict_types=1);

namespace DeviceId\Scoring;

use DeviceId\Network\NetworkFacts;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\TransportIntegrityResult;
use DeviceId\Support\Verdict;

/**
 * Per-rule SHADOW weights: minFraud's `test` disposition for a rule. An operator who wants to know
 * what a new weight, or a rule shipped at weight 0, would do writes it to
 * `fingerprint.constraint_weights_shadow` (code => weight). The live weights keep deciding; this
 * class evaluates the same visit under the tested weights and reports both ({@see ShadowComparison}),
 * so the change can be measured on live traffic, and promoted by moving the number to
 * `constraint_weights` when the comparison looks right.
 *
 * - A tested code with weight 0 is evaluated as silenced; a rule live at 0 and tested at 8 shows
 *   what it WOULD have added whenever it fires.
 * - Only the weights of the codes named in the shadow table differ between the two sides; every
 *   other rule, the transport findings and a model adjustment are carried over from the live
 *   verdict untouched.
 * - Nothing here is applied: the live verdict is not modified, and no shadow weight is ever summed
 *   into it.
 *
 * Compare on the claims the live verdict was computed from; a verdict merged from two tiers
 * (`VerdictScorer::merged()`) is compared on the claims of the tier being judged.
 */
final class ShadowWeights
{
    public function __construct(
        private readonly EnvironmentConsistency $consistency,
        private readonly VerdictScorer $scorer,
    ) {}

    /**
     * @param  array<array-key, mixed>  $claims
     * @param  array<string, int>|null  $shadow  code => weight; null reads `fingerprint.constraint_weights_shadow`
     * @return ShadowComparison|null null when no shadow weight is configured
     */
    public function compare(array $claims, TransportIntegrityResult $transport, ?NetworkFacts $network, Verdict $live, ?array $shadow = null): ?ShadowComparison
    {
        $shadow ??= EnvironmentConsistency::shadowWeights();
        if ($shadow === []) {
            return null;
        }

        $weights = array_replace(EnvironmentConsistency::weights(), $shadow);
        $ruleCodes = array_flip($this->consistency->ruleCodes());

        $disagreements = $this->consistency->contradictionsWith($weights, $claims, $transport, $network);
        foreach ($live->disagreements as $disagreement) {
            if (! isset($ruleCodes[$disagreement['code']])) {
                $disagreement['weight'] = $shadow[$disagreement['code']] ?? $disagreement['weight'];
                if ($disagreement['weight'] > 0 || $disagreement['code'] === 'model_adjustment') {
                    $disagreements[] = $disagreement;
                }
            }
        }

        $shadowWeight = array_sum(array_column($disagreements, 'weight'));
        $shadowScore = $this->scorer->scoreFor($shadowWeight);
        $fired = array_column($disagreements, null, 'code');
        $liveFired = array_column($live->disagreements, null, 'code');

        $changes = [];
        $liveWeights = EnvironmentConsistency::weights();
        foreach ($shadow as $code => $weight) {
            $changes[] = [
                'code' => $code,
                'live_weight' => $liveWeights[$code] ?? 0,
                'shadow_weight' => $weight,
                'fired' => isset($fired[$code]) || isset($liveFired[$code]) || $this->firesAtAll($code, $claims, $transport, $network),
            ];
        }

        return new ShadowComparison(
            $live->totalWeight(),
            $shadowWeight,
            $live->score,
            $shadowScore,
            $live->band,
            $this->scorer->bandFor($shadowScore),
            $changes,
        );
    }

    /**
     * Whether a rule matches the claims at any weight, so a rule that is silenced live (weight 0)
     * still shows up as "fired" when it would have matched.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function firesAtAll(string $code, array $claims, TransportIntegrityResult $transport, ?NetworkFacts $network): bool
    {
        foreach ($this->consistency->contradictionsWith([$code => 1] + array_fill_keys($this->consistency->ruleCodes(), 0), $claims, $transport, $network) as $hit) {
            if ($hit['code'] === $code) {
                return true;
            }
        }

        return false;
    }
}

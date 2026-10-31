<?php

declare(strict_types=1);

namespace DeviceId\Signals;

use DeviceId\Feedback\FeedbackLabel;
use DeviceId\Model\FeatureCatalogue;

/**
 * First-party reputation of a network, from the host's OWN history: the replacement for a bought
 * or credited abuse list. The package stores nothing; the host counts, for one network hash over
 * the window it chooses (seven days is the intended one), how many DISTINCT devices were seen and
 * how many of them an admin later labelled (see {@see FeedbackLabel}).
 *
 * ## Why this is safe to act on softly
 *
 * - **k-floor.** Below `kFloor` distinct devices (default 20) the network is `insufficient`: a
 *   handful of reports on a small network are an accident of who happened to use it.
 * - **Counter-evidence counts.** Every device an admin cleared (`not_abuse`) is subtracted, and a
 *   network with at least as many clearances as reports is `clean` however many reports it has.
 * - **Suspicion is worth half.** A `suspected` label counts 0.5, a confirmed one 1.
 * - It yields ONE soft feature (`net_history_bad`) and never a score, band or block.
 */
final readonly class NetworkReputation
{
    public const INSUFFICIENT = 'insufficient';

    public const CLEAN = 'clean';

    public const BAD = 'bad';

    public function __construct(
        public string $state,
        public int $devices,
        public float $badShare,
    ) {}

    /**
     * @param  int  $devices  distinct device keys seen on the network in the window
     * @param  int  $confirmed  of them, distinct devices an admin labelled `confirmed_fraud`
     * @param  int  $suspected  distinct devices labelled `suspected`
     * @param  int  $cleared  distinct devices labelled `not_abuse`
     */
    public static function assess(int $devices, int $confirmed, int $suspected, int $cleared, ?NetworkReputationThresholds $thresholds = null): self
    {
        $thresholds ??= NetworkReputationThresholds::fromConfig();
        $devices = max(0, $devices);
        if ($devices < $thresholds->kFloor) {
            return new self(self::INSUFFICIENT, $devices, 0.0);
        }

        $bad = max(0, $confirmed) + 0.5 * max(0, $suspected);
        if ($bad < $thresholds->minimumBad || max(0, $cleared) >= max(0, $confirmed) + max(0, $suspected)) {
            return new self(self::CLEAN, $devices, round($bad / $devices, 4));
        }
        $share = $bad / $devices;

        return new self($share >= $thresholds->badShare ? self::BAD : self::CLEAN, $devices, round($share, 4));
    }

    /**
     * @return array<string, float> only the features that hold
     *
     * @see FeatureCatalogue::NETWORK
     */
    public function features(): array
    {
        return $this->state === self::BAD ? ['net_history_bad' => 1.0] : [];
    }
}

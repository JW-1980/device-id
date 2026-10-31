<?php

declare(strict_types=1);

namespace DeviceId\Detectors;

use DeviceId\Model\FeatureCatalogue;

/**
 * The seam for an unsupervised anomaly model (an Isolation Forest over feature vectors), and
 * nothing more. NO implementation ships, by decision.
 *
 * ## The decision (2026-10-31), and what would change it
 *
 * Population COUNTING ({@see RingDetectors}) already answers "which devices, accounts and
 * networks are unusual" and gives a reason a person can read ("5 accounts, 1 device key, 2
 * networks in 24 hours"). An isolation score has no named reason, and learning "normal" from
 * the few machines the harness has would flag every real visitor: Brave farbling, Firefox
 * resistFingerprinting, Safari advanced protection and Linux without fonts all look anomalous
 * by construction. So an anomaly model needs, before it is built:
 *
 * 1. at least several thousand HONEST rows per engine slice (the denominator of "normal");
 * 2. a set of CONFIRMED rings or farms that the counting detectors missed (the evidence that
 *    counting is not enough);
 * 3. a per-slice false-positive measurement that shows privacy-protective browsers are not
 *    over-flagged.
 *
 * Until (2) exists there is nothing for a model to add. A host that builds one implements this
 * interface and routes its output to the review queue only; it must never feed a verdict.
 */
interface AnomalyModel
{
    /**
     * @param  array<string, float>  $features  a vector from {@see FeatureCatalogue::build()}
     * @return float 0 (typical) to 1 (anomalous)
     */
    public function score(array $features): float;

    /** Identifies the model version in the review item evidence. */
    public function id(): string;
}

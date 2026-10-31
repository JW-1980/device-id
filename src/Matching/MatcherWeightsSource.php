<?php

declare(strict_types=1);

namespace DeviceId\Matching;

/**
 * Where the learned matcher weights come from. The host decides (a file it deploys, its
 * settings table, a cache); the package never fetches them.
 */
interface MatcherWeightsSource
{
    /** The weights, or null when there are none or they cannot be trusted. Must not throw. */
    public function load(): ?LearnedWeights;
}

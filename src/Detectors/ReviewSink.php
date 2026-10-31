<?php

declare(strict_types=1);

namespace DeviceId\Detectors;

/**
 * Where findings go. The host implements it over its review queue (a table, a ticket tool); the
 * package has no storage. An implementation must not enforce anything on receipt.
 */
interface ReviewSink
{
    public function enqueue(ReviewItem $item): void;
}

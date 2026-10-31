<?php

declare(strict_types=1);

namespace DeviceId\Support;

/**
 * The one previous observation `TemporalConsistency` needs.
 *
 * ## Why a two-field value object rather than an interface over the model
 *
 * The rule reads exactly TWO things off a previous row: `ja4_correlator` and
 * `user_agent_summary`. Nothing else. So the honest dependency is two nullable strings, and
 * an interface that let a host pass anything with a `->ja4_correlator` property would be a
 * wider contract than the code actually uses — wider contracts are what let a refactor break
 * something that was never touched.
 *
 * Making it a value object also means the package's storage adapter is one `SELECT` of two
 * columns rather than a whole Eloquent model, and the rule cannot accidentally come to depend
 * on a third field.
 */
final class PreviousObservation
{
    public function __construct(
        public readonly ?string $ja4Correlator = null,
        public readonly ?string $userAgentSummary = null,
    ) {}

    /**
     * Whether this row can say anything at all.
     *
     * A row with no JA4 correlator and no UA summary is not "a previous observation that
     * agrees" — it is a row with nothing recorded, and treating it as agreement would let a
     * spoofer pass by ensuring the prior row was uninformative. The rule checks this first
     * for exactly that reason.
     */
    public function isInformative(): bool
    {
        return ($this->ja4Correlator !== null && $this->ja4Correlator !== '')
            || ($this->userAgentSummary !== null && $this->userAgentSummary !== '');
    }
}

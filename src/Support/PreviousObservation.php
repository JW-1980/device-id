<?php

declare(strict_types=1);

namespace DeviceId\Support;

/**
 * The one previous observation `TemporalConsistency` needs.
 *
 * ## Why a four-field value object rather than an interface over the model
 *
 * The rules read exactly FOUR things off a previous row: `ja4_correlator`, `user_agent_summary`,
 * the `block_tuple` hash and the measured engine. Nothing else. So the honest dependency is four nullable strings, and
 * an interface that let a host pass anything with a `->ja4_correlator` property would be a
 * wider contract than the code actually uses — wider contracts are what let a refactor break
 * something that was never touched.
 *
 * Making it a value object also means the package's storage adapter is one `SELECT` of four
 * columns rather than a whole Eloquent model, and the rule cannot accidentally come to depend
 * on a fifth field.
 */
final class PreviousObservation
{
    public function __construct(
        public readonly ?string $ja4Correlator = null,
        public readonly ?string $userAgentSummary = null,
        /**
         * The unkeyed `block_tuple` hash the host already stores per observation
         * (`DeviceComponents::blockTuple()`: sha256 of os|arch|touch). Not a claim value; read only
         * by `temporal_hard_component_changed`, and only when the host picked this row by cookie or
         * browser key.
         */
        public readonly ?string $blockTuple = null,
        /**
         * The engine that observation measured, `EnvironmentConsistency::measuredEngine()`
         * (`chromium`|`gecko`|`webkit`|`lightpanda`). A class word, not a claim value; read only by
         * `temporal_engine_changed`, and only when the host picked this row by cookie.
         */
        public readonly ?string $engine = null,
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
            || ($this->userAgentSummary !== null && $this->userAgentSummary !== '')
            || ($this->blockTuple !== null && $this->blockTuple !== '')
            || ($this->engine !== null && $this->engine !== '');
    }
}

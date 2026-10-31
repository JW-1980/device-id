<?php

declare(strict_types=1);

namespace DeviceId\Reputation;

use DeviceId\Model\FeatureCatalogue;

/**
 * What the feeds say about one address: categories, sources, and how complete the answer is.
 *
 * ## An address alone never blocks
 *
 * This object carries no score, band or weight, on purpose. A datacenter address is also a
 * VPN, a corporate proxy, iCloud Private Relay or a developer's laptop; a listed address is
 * also a shared NAT. It is exposed two ways and both are soft: {@see features()} (named
 * features a model may use, 0 when absent) and {@see ruleInput()} (facts a rule may combine
 * with other evidence). A rule that blocks on this alone is a defect.
 *
 * `state`: `ok` every enabled feed was fresh; `partial` some were stale, never fetched or
 * unaccepted (their silence is NOT a clean answer); `unavailable` none could be used. Absence
 * of data is "no signal", never "clean" and never "listed".
 */
final readonly class ReputationResult
{
    public const STATE_OK = 'ok';

    public const STATE_PARTIAL = 'partial';

    public const STATE_UNAVAILABLE = 'unavailable';

    /**
     * @param  list<string>  $categories  `datacenter`, `tor_exit`, `abuse_list`
     * @param  list<string>  $sources  feed keys that matched
     * @param  list<string>  $unusableFeeds  feed keys that were stale, missing or unaccepted
     * @param  list<string>  $attribution  credit lines the matched feeds require
     */
    public function __construct(
        public string $state,
        public array $categories = [],
        public array $sources = [],
        public array $unusableFeeds = [],
        public array $attribution = [],
    ) {}

    public static function unavailable(array $unusableFeeds = []): self
    {
        return new self(self::STATE_UNAVAILABLE, [], [], $unusableFeeds);
    }

    public function isDatacenter(): bool
    {
        return in_array(FeedDefinition::CATEGORY_DATACENTER, $this->categories, true);
    }

    public function isTorExit(): bool
    {
        return in_array(FeedDefinition::CATEGORY_TOR_EXIT, $this->categories, true);
    }

    public function isAbuseListed(): bool
    {
        return in_array(FeedDefinition::CATEGORY_ABUSE_LIST, $this->categories, true);
    }

    /**
     * Named features for {@see FeatureCatalogue::build()}: only those that hold.
     *
     * @return array<string, float>
     */
    public function features(): array
    {
        return array_filter([
            'rep_datacenter' => $this->isDatacenter() ? 1.0 : 0.0,
            'rep_tor_exit' => $this->isTorExit() ? 1.0 : 0.0,
            'rep_abuse_listed' => $this->isAbuseListed() ? 1.0 : 0.0,
        ], static fn (float $v): bool => $v > 0.0);
    }

    /**
     * Facts for a rule to combine with other evidence. `known` is false when the answer is
     * `unavailable`, so a rule can tell "not listed" from "no list".
     *
     * @return array{known: bool, complete: bool, datacenter: bool, tor_exit: bool, abuse_listed: bool}
     */
    public function ruleInput(): array
    {
        return [
            'known' => $this->state !== self::STATE_UNAVAILABLE,
            'complete' => $this->state === self::STATE_OK,
            'datacenter' => $this->isDatacenter(),
            'tor_exit' => $this->isTorExit(),
            'abuse_listed' => $this->isAbuseListed(),
        ];
    }
}

<?php

declare(strict_types=1);

namespace DeviceId\Network;

use DeviceId\Model\FeatureCatalogue;
use DeviceId\Reputation\ReputationResult;

/**
 * What the local network data says about one address: the country it geolocates to, the
 * autonomous system that announces it and a coarse category of that system. It carries no
 * score. A rule or a model reads it as one soft fact among many, because a hosting address is
 * also a VPN, a corporate gateway and a developer's laptop, and a country is a database's
 * best guess (DB-IP states country accuracy as high, not perfect).
 *
 * Unknown stays unknown: a null country or category means "no data", never "clean" and never
 * "domestic". {@see $state}: `ok` every dataset answered, `partial` some were stale, missing or
 * not yet fetched, `unavailable` none could be used.
 *
 * A host that already has these facts from its edge (a CDN country header, its own ASN lookup)
 * can build the object directly and skip {@see NetworkDatabase}.
 */
final readonly class NetworkFacts
{
    public const STATE_OK = 'ok';

    public const STATE_PARTIAL = 'partial';

    public const STATE_UNAVAILABLE = 'unavailable';

    /** An autonomous system of a hosting, cloud or colocation provider. */
    public const CATEGORY_HOSTING = 'hosting';

    /** An autonomous system whose registered name says it is a VPN service. */
    public const CATEGORY_VPN = 'vpn';

    /**
     * @param  string|null  $country  ISO 3166-1 alpha-2, upper case
     * @param  string|null  $asnCategory  {@see CATEGORY_HOSTING}, {@see CATEGORY_VPN} or null (no flag; NOT "residential")
     * @param  bool  $datacenterRange  the address is inside a published cloud range ({@see ReputationResult})
     * @param  list<string>  $unusable  datasets that were stale, missing or unaccepted
     * @param  list<string>  $attribution  credit lines the answering datasets require
     */
    public function __construct(
        public string $state = self::STATE_UNAVAILABLE,
        public ?string $country = null,
        public ?int $asn = null,
        public ?string $asnCategory = null,
        public bool $datacenterRange = false,
        public bool $torExit = false,
        public array $unusable = [],
        public array $attribution = [],
    ) {}

    public static function unknown(): self
    {
        return new self;
    }

    /**
     * The same facts with the IP-reputation answer folded in (cloud ranges, Tor exits).
     */
    public function withReputation(ReputationResult $reputation): self
    {
        return new self(
            $this->state,
            $this->country,
            $this->asn,
            $this->asnCategory,
            $this->datacenterRange || $reputation->isDatacenter(),
            $this->torExit || $reputation->isTorExit(),
            $this->unusable,
            array_values(array_unique([...$this->attribution, ...$reputation->attribution])),
        );
    }

    public function isVpn(): bool
    {
        return $this->asnCategory === self::CATEGORY_VPN;
    }

    /**
     * Hosting, cloud or colocation: a hosting ASN or a published cloud range. A VPN-named ASN is
     * reported by {@see isVpn()} instead and is not counted here, so one address never pays for
     * both.
     */
    public function isHosting(): bool
    {
        return ! $this->isVpn() && ($this->asnCategory === self::CATEGORY_HOSTING || $this->datacenterRange);
    }

    /**
     * Soft model features ({@see FeatureCatalogue::NETWORK}); only those that hold.
     *
     * @return array<string, float>
     */
    public function features(): array
    {
        return array_filter([
            'net_hosting' => $this->isHosting() ? 1.0 : 0.0,
            'net_vpn' => $this->isVpn() ? 1.0 : 0.0,
            'net_tor_exit' => $this->torExit ? 1.0 : 0.0,
        ], static fn (float $v): bool => $v > 0.0);
    }

    /**
     * The only network context a training row may carry: a country code and a category bucket.
     * No address, no ASN number.
     *
     * @return array{country: string, asn_category: string}
     */
    public function trainingBuckets(): array
    {
        return [
            'country' => $this->country ?? 'unknown',
            'asn_category' => match (true) {
                $this->state === self::STATE_UNAVAILABLE && ! $this->datacenterRange && ! $this->torExit => 'unknown',
                $this->torExit => 'tor',
                $this->isVpn() => 'vpn',
                $this->isHosting() => 'hosting',
                default => 'other',
            },
        ];
    }
}

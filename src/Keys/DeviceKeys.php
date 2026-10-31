<?php

declare(strict_types=1);

namespace DeviceId\Keys;

/**
 * The two keys and the quantised components one claim set derives.
 *
 * `browserKey` is the HMAC of the stabilised tier-1 claims (engine-level identity, the
 * legacy `device_key`). `hardwareKey` is the HMAC of the hard component tuple
 * (`DeviceComponents::HARD`: os, arch, touch), null unless all three are known.
 * `coverage` is the share of expected components that are non-null, 0..1.
 *
 * `protected` is true when the claim set comes from Firefox resistFingerprinting or Tor
 * Browser under the engine evidence gate (`DeviceComponents::protectedGecko()`). Such a
 * browser's `browserKey` is shared by everyone running the same protection, window bucket and
 * version, so `DeviceMatcher` never links a protected set by key: it is a new device.
 *
 * `untrusted` is `DeviceComponents::untrusted()` for the same claim set, the component names
 * nulled in `components`; kept so a caller that stores the decision (`FingerprintIngest`)
 * does not compute it a second time.
 */
final readonly class DeviceKeys
{
    /**
     * @param  array<string, scalar|null>  $components
     * @param  list<string>  $untrusted
     */
    public function __construct(
        public ?string $browserKey,
        public ?string $hardwareKey,
        public array $components,
        public float $coverage,
        public int $saltVersion,
        public bool $protected = false,
        public array $untrusted = [],
    ) {}
}

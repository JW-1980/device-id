<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Crawlers;

/**
 * The operator's own allowlist: IP addresses and CIDRs, and device keys. Configured by the host;
 * empty by default, so nothing is allowed that the operator did not name.
 *
 * Entries are validated once. An invalid entry (a typo, `10.0.0.0/33`, a /0 that would allow every
 * address) is NOT silently dropped: it is kept in `invalidEntries()` so the host can log or show it,
 * and it never matches anything.
 *
 * A device key is a recognition handle, not a credential (a fingerprint can be copied), so a
 * device-key entry is as strong as the key is hard to obtain. Prefer IPs for anything that must not
 * be spoofable.
 */
final class OperatorAllowlist
{
    /** @var list<array{0: string, 1: int, 2: string}> packed network, bits, original entry */
    private array $networks = [];

    /** @var list<string> */
    private array $deviceKeys = [];

    /** @var list<string> */
    private array $invalid = [];

    /**
     * @param  iterable<mixed>  $ips  addresses and CIDRs
     * @param  iterable<mixed>  $deviceKeys
     */
    public function __construct(iterable $ips = [], iterable $deviceKeys = [])
    {
        foreach ($ips as $entry) {
            if (! is_string($entry) || trim($entry) === '') {
                if (! is_string($entry) || $entry !== '') {
                    $this->invalid[] = is_scalar($entry) ? (string) $entry : get_debug_type($entry);
                }

                continue;
            }

            $parsed = IpAddress::parseCidr($entry);
            if ($parsed === null) {
                $this->invalid[] = trim($entry);

                continue;
            }

            $this->networks[] = [$parsed[0], $parsed[1], trim($entry)];
        }

        foreach ($deviceKeys as $key) {
            if (is_string($key) && trim($key) !== '') {
                $this->deviceKeys[] = trim($key);
            }
        }
    }

    /**
     * @param  array<array-key, mixed>  $config  keys: ips, device_keys
     */
    public static function fromArray(array $config): self
    {
        $ips = $config['ips'] ?? [];
        $keys = $config['device_keys'] ?? [];

        return new self(is_array($ips) ? $ips : [], is_array($keys) ? $keys : []);
    }

    /** The entry that matched, or null. */
    public function matchIp(string $ip): ?string
    {
        $packed = IpAddress::pack($ip);
        if ($packed === null) {
            return null;
        }

        foreach ($this->networks as [$network, $bits, $entry]) {
            if (IpAddress::packedInCidr($packed, $network, $bits)) {
                return $entry;
            }
        }

        return null;
    }

    public function matchesIp(string $ip): bool
    {
        return $this->matchIp($ip) !== null;
    }

    public function matchesDeviceKey(?string $deviceKey): bool
    {
        if ($deviceKey === null || $deviceKey === '') {
            return false;
        }

        foreach ($this->deviceKeys as $allowed) {
            if (hash_equals($allowed, $deviceKey)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function invalidEntries(): array
    {
        return $this->invalid;
    }

    public function isEmpty(): bool
    {
        return $this->networks === [] && $this->deviceKeys === [];
    }
}

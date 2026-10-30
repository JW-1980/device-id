<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Matching;

/**
 * The `MatchCandidate` accessors for an Eloquent device row with `id`, `cluster_id`,
 * `components`, `browser_key` and `hardware_key` columns. One implementation for both
 * device stores (code-quality review CQ-17).
 *
 * @property int $id
 * @property int|null $cluster_id
 * @property array<string, scalar|null>|null $components
 * @property string|null $browser_key
 * @property string|null $hardware_key
 * @property string|null $link_network
 */
trait MatchesAsCandidate
{
    public function matchId(): int
    {
        return $this->id;
    }

    public function matchClusterId(): int
    {
        return $this->cluster_id ?? $this->id;
    }

    /**
     * @return array<string, scalar|null>
     */
    public function matchComponents(): array
    {
        if (! $this->componentsAreMatchable()) {
            return [];
        }

        $components = $this->components;
        $out = [];
        foreach (is_array($components) ? $components : [] as $name => $value) {
            if (is_string($name) && ($value === null || is_scalar($value))) {
                $out[$name] = $value;
            }
        }

        return $out;
    }

    public function matchBrowserKey(): ?string
    {
        return is_string($this->browser_key) ? $this->browser_key : null;
    }

    public function matchHardwareKey(): ?string
    {
        return is_string($this->hardware_key) ? $this->hardware_key : null;
    }

    /**
     * The same-network token: `link_network`, the keyed code of the IPv4 /24 or IPv6 /56
     * last reported from (the application's `LinkNetwork`). Both stores keep the address itself only
     * encrypted (EncryptedIp), so equality runs on this code, never on a stored prefix.
     */
    public function matchNetwork(): ?string
    {
        return is_string($this->link_network) && $this->link_network !== '' ? $this->link_network : null;
    }

    /**
     * Whether the row's `components` are `DeviceComponents` classes (a legacy
     * FingerprintJS row holds hashes of another kind there).
     */
    protected function componentsAreMatchable(): bool
    {
        return true;
    }
}

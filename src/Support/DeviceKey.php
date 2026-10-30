<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Support;

/**
 * A derived device key, with the salt version that produced it.
 *
 * Carrying the version alongside the key is what makes rotation a scheduled,
 * prunable operation rather than a migration. Rows written under an old salt stay
 * comparable to each other and are identifiable as a generation, so a rotation can
 * let the old generation age out on the normal retention schedule instead of
 * requiring a blocking rewrite of the table.
 */
final readonly class DeviceKey
{
    /**
     * How many leading characters of a key name the device to a person: the
     * reference a refusal quotes, the prefix the admin device screens show and
     * filter on (*Automatic device blocks*), and the prefix logs carry instead
     * of the key. One number, so a refusal's reference always finds its row.
     */
    public const REFERENCE_LENGTH = 12;

    public function __construct(
        public string $key,
        public int $saltVersion,
    ) {}

    /**
     * The reference for a device key: its first {@see self::REFERENCE_LENGTH}
     * characters, never the key itself (the key is what the device is
     * recognised by). Null for a missing or blank key.
     */
    public static function reference(?string $key): ?string
    {
        if ($key === null) {
            return null;
        }

        $key = trim($key);

        return $key === '' ? null : substr($key, 0, self::REFERENCE_LENGTH);
    }

    public function equals(self $other): bool
    {
        return $this->saltVersion === $other->saltVersion
            && hash_equals($this->key, $other->key);
    }
}

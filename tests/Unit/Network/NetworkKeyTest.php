<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Network;

use DeviceId\Network\NetworkKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Network keys for rate limits (skeptical review M2): one IPv6 /48, which free tunnel brokers
 * route to anyone, held 256 distinct /56 "networks" and so 256 counted guest votes per duel.
 */
final class NetworkKeyTest extends TestCase
{
    #[Test]
    public function every_56_inside_one_48_is_one_limit_key(): void
    {
        $keys = [];
        for ($i = 0; $i < 256; $i += 13) {
            $keys[] = NetworkKey::forLimits(sprintf('2001:db8:1:%02x00::1', $i));
        }

        $this->assertCount(1, array_unique($keys));
        $this->assertSame('v6:2001:db8:1::/48', $keys[0]);
        $this->assertNotSame(NetworkKey::forLimits('2001:db8:1::1'), NetworkKey::forLimits('2001:db8:2::1'), 'another /48 is another key');
    }

    #[Test]
    public function the_end_site_key_keeps_one_56_per_household(): void
    {
        $this->assertSame('v6:2001:db8:1:ab00::/56', NetworkKey::endSite('2001:db8:1:abcd::1'));
        $this->assertNotSame(NetworkKey::endSite('2001:db8:1:ab00::1'), NetworkKey::endSite('2001:db8:1:ac00::1'));
        $this->assertSame(NetworkKey::forLimits('2001:db8:1:ab00::1'), NetworkKey::forLimits('2001:db8:1:ac00::1'));
    }

    /** @return iterable<string, array{string, ?string, ?string}> */
    public static function addresses(): iterable
    {
        yield 'IPv4 is one address' => ['203.0.113.77', 'v4:203.0.113.77/32', 'v4:203.0.113.77/32'];
        yield 'IPv4-mapped IPv6 folds to IPv4' => ['::ffff:203.0.113.77', 'v4:203.0.113.77/32', 'v4:203.0.113.77/32'];
        yield 'uncompressed spelling' => ['2001:0db8:0001:0002:0000:0000:0000:0001', 'v6:2001:db8:1::/48', 'v6:2001:db8:1::/56'];
        yield 'garbage' => ['not an ip', null, null];
        yield 'empty' => ['', null, null];
        yield 'with a port' => ['203.0.113.77:443', null, null];
    }

    #[Test]
    #[DataProvider('addresses')]
    public function addresses_are_canonicalised_and_invalid_input_has_no_key(string $ip, ?string $limit, ?string $site): void
    {
        $this->assertSame($limit, NetworkKey::forLimits($ip));
        $this->assertSame($site, NetworkKey::endSite($ip));
    }

    #[Test]
    public function a_keyed_form_hides_the_prefix_and_depends_on_the_secret(): void
    {
        $secret = str_repeat('k', 32);
        $a = NetworkKey::keyed('2001:db8:1:ab00::1', $secret);

        $this->assertSame($a, NetworkKey::keyed('2001:db8:1:cd00::9', $secret), 'one /48, one key');
        $this->assertNotSame($a, NetworkKey::keyed('2001:db8:1:ab00::1', str_repeat('j', 32)));
        $this->assertStringNotContainsString('2001', (string) $a);
        $this->assertNull(NetworkKey::keyed('2001:db8::1', 'short'), 'a short secret is refused, never an unkeyed hash');
        $this->assertNull(NetworkKey::keyed('nope', $secret));
    }
}

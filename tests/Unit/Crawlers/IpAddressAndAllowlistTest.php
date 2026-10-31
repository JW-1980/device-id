<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Crawlers;

use NutriCompare\Fingerprint\Crawlers\HostnameSuffix;
use NutriCompare\Fingerprint\Crawlers\OperatorAllowlist;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class IpAddressAndAllowlistTest extends TestCase
{
    /** @return iterable<string, array{string, string, bool}> */
    public static function cidrEdges(): iterable
    {
        yield 'v4 first address' => ['192.0.2.0', '192.0.2.0/24', true];
        yield 'v4 last address' => ['192.0.2.255', '192.0.2.0/24', true];
        yield 'v4 one below' => ['192.0.1.255', '192.0.2.0/24', false];
        yield 'v4 one above' => ['192.0.3.0', '192.0.2.0/24', false];
        yield 'v4 /32 exact' => ['203.0.113.7', '203.0.113.7/32', true];
        yield 'v4 /32 neighbour' => ['203.0.113.8', '203.0.113.7/32', false];
        yield 'v4 /31 pair low' => ['198.51.100.4', '198.51.100.4/31', true];
        yield 'v4 /31 pair high' => ['198.51.100.5', '198.51.100.4/31', true];
        yield 'v4 /31 outside' => ['198.51.100.6', '198.51.100.4/31', false];
        yield 'v4 non-byte boundary /20 inside' => ['10.0.15.255', '10.0.0.0/20', true];
        yield 'v4 non-byte boundary /20 outside' => ['10.0.16.0', '10.0.0.0/20', false];
        yield 'v4 /1' => ['127.255.255.255', '0.0.0.0/1', true];
        yield 'v4 /1 outside' => ['128.0.0.0', '0.0.0.0/1', false];
        yield 'bare v4 is a host prefix' => ['203.0.113.7', '203.0.113.7', true];
        yield 'bare v4 neighbour' => ['203.0.113.6', '203.0.113.7', false];
        yield 'v6 inside /32' => ['2001:db8:ffff::1', '2001:db8::/32', true];
        yield 'v6 outside /32' => ['2001:db9::1', '2001:db8::/32', false];
        yield 'v6 /128 exact' => ['2001:db8::1', '2001:db8::1/128', true];
        yield 'v6 /128 neighbour' => ['2001:db8::2', '2001:db8::1/128', false];
        yield 'v6 spelled long' => ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1', true];
        yield 'v6 non-nibble /33' => ['2001:db8:7fff::1', '2001:db8::/33', true];
        yield 'v6 non-nibble /33 outside' => ['2001:db8:8000::1', '2001:db8::/33', false];
        yield 'v4 client is not in a v6 prefix' => ['192.0.2.1', '2001:db8::/32', false];
        yield 'v6 client is not in a v4 prefix' => ['2001:db8::1', '192.0.2.0/24', false];
        yield 'v4-mapped client matches a v4 range' => ['::ffff:192.0.2.9', '192.0.2.0/24', true];
        yield 'v4-mapped client outside a v4 range' => ['::ffff:192.0.3.9', '192.0.2.0/24', false];
    }

    #[Test]
    #[DataProvider('cidrEdges')]
    public function allowlist_cidr_edges(string $ip, string $entry, bool $expected): void
    {
        self::assertSame($expected, (new OperatorAllowlist([$entry]))->matchesIp($ip));
    }

    #[Test]
    public function invalid_entries_never_match_and_are_reported(): void
    {
        $list = new OperatorAllowlist(['10.0.0.0/33', 'not-an-ip', '0.0.0.0/0', '::/0', '2001:db8::/129', '10.0.0.0/-1', '10.0.0.0/', '203.0.113.7']);

        self::assertSame(['10.0.0.0/33', 'not-an-ip', '0.0.0.0/0', '::/0', '2001:db8::/129', '10.0.0.0/-1', '10.0.0.0/'], $list->invalidEntries());
        self::assertFalse($list->matchesIp('10.0.0.1'), 'a /33 typo must not allow the network');
        self::assertFalse($list->matchesIp('8.8.8.8'), 'a /0 must not allow everything');
        self::assertFalse($list->matchesIp('2001:db8::1'));
        self::assertTrue($list->matchesIp('203.0.113.7'), 'the valid entry still works');
    }

    #[Test]
    public function garbage_addresses_never_match(): void
    {
        $list = new OperatorAllowlist(['10.0.0.0/8']);

        foreach (['', 'garbage', '10.0.0', '10.0.0.256', '10.0.0.1/8', "10.0.0.1\n"] as $ip) {
            self::assertFalse($list->matchesIp($ip), var_export($ip, true));
        }
    }

    #[Test]
    public function the_matching_entry_is_reported(): void
    {
        $list = new OperatorAllowlist(['198.51.100.0/24', '10.0.0.0/8']);

        self::assertSame('10.0.0.0/8', $list->matchIp('10.9.9.9'));
        self::assertNull($list->matchIp('11.0.0.1'));
    }

    #[Test]
    public function device_keys_match_exactly(): void
    {
        $list = OperatorAllowlist::fromArray(['device_keys' => ['abc123', '', 7], 'ips' => []]);

        self::assertTrue($list->matchesDeviceKey('abc123'));
        self::assertFalse($list->matchesDeviceKey('ABC123'));
        self::assertFalse($list->matchesDeviceKey('abc12'));
        self::assertFalse($list->matchesDeviceKey('abc1234'));
        self::assertFalse($list->matchesDeviceKey(''));
        self::assertFalse($list->matchesDeviceKey(null));
        self::assertFalse((new OperatorAllowlist)->matchesDeviceKey('abc123'));
        self::assertTrue((new OperatorAllowlist)->isEmpty());
    }

    /** @return iterable<string, array{string, bool}> */
    public static function hostnames(): iterable
    {
        yield 'genuine' => ['crawl-66-249-66-1.googlebot.com', true];
        yield 'the bare domain' => ['googlebot.com', true];
        yield 'trailing dot, mixed case' => ['Crawl-1.GoogleBot.com.', true];
        yield 'prefix attack' => ['evil-googlebot.com', false];
        yield 'suffix as a label of another domain' => ['googlebot.com.evil.net', false];
        yield 'one label short' => ['notgooglebot.com', false];
        yield 'different tld' => ['crawl-1.googlebot.co', false];
        yield 'empty' => ['', false];
    }

    #[Test]
    #[DataProvider('hostnames')]
    public function suffix_matching_is_on_label_boundaries(string $host, bool $expected): void
    {
        self::assertSame($expected, HostnameSuffix::matches($host, ['googlebot.com']));
    }

    #[Test]
    public function an_empty_suffix_never_matches(): void
    {
        self::assertFalse(HostnameSuffix::matches('anything.example', ['', '.']));
    }
}

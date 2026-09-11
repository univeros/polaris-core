<?php

declare(strict_types=1);

namespace Polaris\Admin\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\Principal\IpAllowlist;

#[CoversClass(IpAllowlist::class)]
final class IpAllowlistTest extends TestCase
{
    public function testEmptyAllowsAnywhereAndANonEmptyListNeedsAnAddress(): void
    {
        self::assertTrue(IpAllowlist::allows([], null));
        self::assertTrue(IpAllowlist::allows([], '203.0.113.7'));
        self::assertFalse(IpAllowlist::allows(['203.0.113.7'], null));
        self::assertFalse(IpAllowlist::allows(['203.0.113.7'], 'not an address'));
    }

    public function testExactAddressesAndCidrBlocksOfBothFamilies(): void
    {
        self::assertTrue(IpAllowlist::allows(['203.0.113.7'], '203.0.113.7'));
        self::assertFalse(IpAllowlist::allows(['203.0.113.7'], '203.0.113.8'));
        self::assertTrue(IpAllowlist::allows(['10.0.0.0/8'], '10.200.1.1'));
        self::assertFalse(IpAllowlist::allows(['10.0.0.0/8'], '11.0.0.1'));
        self::assertTrue(IpAllowlist::allows(['192.168.4.0/22'], '192.168.7.255'));
        self::assertFalse(IpAllowlist::allows(['192.168.4.0/22'], '192.168.8.0'));
        self::assertTrue(IpAllowlist::allows(['2001:db8::/32'], '2001:db8:1::5'));
        self::assertFalse(IpAllowlist::allows(['2001:db8::/32'], '2001:db9::1'));
        self::assertFalse(IpAllowlist::allows(['10.0.0.0/8'], '::ffff:10.0.0.1'), 'families do not mix');
        self::assertTrue(IpAllowlist::allows(['0.0.0.0/0'], '8.8.8.8'));
    }

    public function testValidation(): void
    {
        self::assertTrue(IpAllowlist::isValid('203.0.113.7'));
        self::assertTrue(IpAllowlist::isValid('10.0.0.0/8'));
        self::assertTrue(IpAllowlist::isValid('2001:db8::/32'));
        self::assertFalse(IpAllowlist::isValid('10.0.0.0/33'));
        self::assertFalse(IpAllowlist::isValid('example.test'));
        self::assertFalse(IpAllowlist::isValid('10.0.0.0/abc'));
    }
}

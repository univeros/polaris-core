<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Model;

use PHPUnit\Framework\TestCase;
use Polaris\Model\Membership;

final class MembershipTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $membership = new Membership();

        self::assertSame('', $membership->id);
        self::assertSame('', $membership->userId);
        self::assertSame('', $membership->organizationId);
        self::assertSame(Membership::STATUS_INVITED, $membership->status);
        self::assertNull($membership->invitedBy);
        self::assertNull($membership->joinedAt);
    }

    public function testExposesTheStatusValues(): void
    {
        self::assertSame('invited', Membership::STATUS_INVITED);
        self::assertSame('active', Membership::STATUS_ACTIVE);
        self::assertSame('suspended', Membership::STATUS_SUSPENDED);
    }
}

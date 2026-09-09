<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Model;

use PHPUnit\Framework\TestCase;
use Polaris\Model\MembershipRole;

final class MembershipRoleTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $grant = new MembershipRole();

        self::assertSame('', $grant->membershipId);
        self::assertSame('', $grant->roleId);
    }
}

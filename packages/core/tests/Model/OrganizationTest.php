<?php

declare(strict_types=1);

namespace Polaris\Tests\Model;

use PHPUnit\Framework\TestCase;
use Polaris\Model\Organization;

final class OrganizationTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $organization = new Organization();

        self::assertSame('', $organization->id);
        self::assertSame('', $organization->name);
        self::assertSame('', $organization->slug);
        self::assertSame(Organization::STATUS_ACTIVE, $organization->status);
        self::assertSame('', $organization->createdBy);
    }

    public function testExposesTheStatusValues(): void
    {
        self::assertSame('active', Organization::STATUS_ACTIVE);
        self::assertSame('suspended', Organization::STATUS_SUSPENDED);
    }
}

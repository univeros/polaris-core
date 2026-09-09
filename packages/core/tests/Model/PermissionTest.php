<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Model;

use PHPUnit\Framework\TestCase;
use Polaris\Model\Permission;

final class PermissionTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $permission = new Permission();

        self::assertSame('', $permission->id);
        self::assertSame('', $permission->key);
        self::assertSame('', $permission->description);
    }
}

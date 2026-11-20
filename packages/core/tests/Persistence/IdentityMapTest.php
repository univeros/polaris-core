<?php

declare(strict_types=1);

namespace Polaris\Tests\Persistence;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Repository\IdentityMap;
use stdClass;

#[CoversClass(IdentityMap::class)]
final class IdentityMapTest extends TestCase
{
    /**
     * A row is kept per spl_object_id: the row of an object replaced under its key must go with it, or
     * a later object allocated under the freed id passes for it and its insert is skipped as an update.
     */
    public function testAnObjectReplacedUnderItsKeyLeavesNoRowBehind(): void
    {
        $map = new IdentityMap();
        $first = new stdClass();
        $second = new stdClass();
        $map->remember($first, 'k', ['v' => 1]);
        $map->remember($second, 'k', ['v' => 2]);

        self::assertNull($map->rowOf($first));
        self::assertSame(['v' => 2], $map->rowOf($second));
        self::assertSame($second, $map->get(stdClass::class, 'k'));
        $map->remember($second, 'k', ['v' => 3]);
        self::assertSame(['v' => 3], $map->rowOf($second), 'remembering the same object again keeps it');
    }
}

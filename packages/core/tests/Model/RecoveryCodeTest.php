<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Model;

use PHPUnit\Framework\TestCase;
use Polaris\Model\RecoveryCode;

final class RecoveryCodeTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $code = new RecoveryCode();

        self::assertSame('', $code->id);
        self::assertSame('', $code->userId);
        self::assertSame('', $code->codeHash);
        self::assertNull($code->usedAt);
    }
}

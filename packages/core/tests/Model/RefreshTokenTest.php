<?php

declare(strict_types=1);

namespace Polaris\Tests\Model;

use PHPUnit\Framework\TestCase;
use Polaris\Model\RefreshToken;

final class RefreshTokenTest extends TestCase
{
    public function testHasSensibleDefaults(): void
    {
        $token = new RefreshToken();

        self::assertSame('', $token->id);
        self::assertSame('', $token->userId);
        self::assertSame('', $token->familyId);
        self::assertSame('', $token->tokenHash);
        self::assertNull($token->organizationId);
        self::assertNull($token->parentId);
        self::assertNull($token->userAgent);
        self::assertNull($token->ip);
        self::assertNull($token->lastUsedAt);
        self::assertNull($token->revokedAt);
        self::assertNull($token->revokedReason);
    }
}

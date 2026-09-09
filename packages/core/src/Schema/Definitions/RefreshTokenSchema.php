<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\RefreshToken;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class RefreshTokenSchema
{
    public static function define(): Model
    {
        return Model::table('auth_refresh_tokens', RefreshToken::class, [
            Field::string('id', 36)->primary(),
            Field::string('userId', 36),
            Field::string('organizationId', 36)->nullable(),
            Field::string('familyId', 36),
            Field::string('parentId', 36)->nullable(),
            Field::string('tokenHash', 64),
            Field::string('userAgent', 255)->nullable(),
            Field::string('ip', 45)->nullable(),
            Field::bool('mfa')->default(false),
            Field::string('amr', 64)->nullable(),
            Field::int('authTime')->nullable(),
            Field::datetime('expiresAt'),
            Field::datetime('lastUsedAt')->nullable(),
            Field::datetime('revokedAt')->nullable(),
            Field::string('revokedReason', 32)->nullable(),
            Field::datetime('createdAt'),
        ])
            ->unique(['token_hash'], 'auth_refresh_tokens_token_hash_unique')
            ->index(['user_id', 'revoked_at'], 'auth_refresh_tokens_user_index')
            ->index(['family_id'], 'auth_refresh_tokens_family_index');
    }
}

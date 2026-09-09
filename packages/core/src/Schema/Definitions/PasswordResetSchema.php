<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\PasswordReset;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class PasswordResetSchema
{
    public static function define(): Model
    {
        return Model::table('auth_password_resets', PasswordReset::class, [
            Field::string('id', 36)->primary(),
            Field::string('userId', 36),
            Field::string('email', 320),
            Field::string('tokenHash', 64),
            Field::datetime('expiresAt'),
            Field::datetime('consumedAt')->nullable(),
            Field::string('ip', 45)->nullable(),
            Field::datetime('createdAt'),
        ])
            ->unique(['token_hash'], 'auth_password_resets_token_hash_unique')
            ->index(['user_id'], 'auth_password_resets_user_index')
            ->index(['expires_at'], 'auth_password_resets_expires_index');
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\User;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class UserSchema
{
    public static function define(): Model
    {
        return Model::table('auth_users', User::class, [
            Field::string('id', 36)->primary(),
            Field::string('email', 320),
            Field::datetime('emailVerifiedAt')->nullable(),
            Field::string('passwordHash', 255)->nullable(),
            Field::string('displayName', 120)->nullable(),
            Field::string('status', 16)->default('active'),
            Field::bool('mfaEnforced')->default(false),
            Field::int('failedLoginCount')->default(0),
            Field::datetime('failedLoginAt')->nullable(),
            Field::datetime('lockedUntil')->nullable(),
            Field::datetime('lastLoginAt')->nullable(),
            Field::datetime('createdAt'),
            Field::datetime('updatedAt'),
        ])
            ->unique(['email'], 'auth_users_email_unique')
            ->index(['status'], 'auth_users_status_index');
    }
}

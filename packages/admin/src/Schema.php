<?php

declare(strict_types=1);

namespace Polaris\Admin;

use Polaris\Admin\Model\AdminGrant;
use Polaris\Admin\Model\AdminKey;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The two tables the plugin owns.
 */
final class Schema
{
    public const string GRANTS = 'polaris_admin_grant';
    public const string KEYS = 'polaris_admin_key';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::GRANTS, AdminGrant::class, [
                Field::string('id', 36)->primary(),
                Field::string('userId', 36),
                Field::string('role', 16),
                Field::string('scope', 36),
                Field::string('grantedBy', 36)->nullable(),
                Field::datetime('expiresAt')->nullable(),
                Field::datetime('createdAt'),
            ])->index(['user_id'], 'polaris_admin_grant_user_index'),
            Model::table(self::KEYS, AdminKey::class, [
                Field::string('id', 36)->primary(),
                Field::string('name', 120),
                Field::string('keyHash', 64),
                Field::string('role', 16),
                Field::string('scope', 36),
                Field::json('ipAllowlist'),
                Field::datetime('expiresAt')->nullable(),
                Field::datetime('lastUsedAt')->nullable(),
                Field::string('createdBy', 64)->nullable(),
                Field::datetime('createdAt'),
            ])->unique(['key_hash'], 'polaris_admin_key_hash_unique'),
        ];
    }
}

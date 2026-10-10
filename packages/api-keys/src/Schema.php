<?php

declare(strict_types=1);

namespace Polaris\ApiKeys;

use Polaris\ApiKeys\Model\ApiKey;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The table the plugin owns: the API keys of users and organizations, stored as keyed hashes with the
 * permissions, rate limit, expiry, rotation and revocation state of each.
 */
final class Schema
{
    public const string KEYS = 'polaris_api_key';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::KEYS, ApiKey::class, [
                Field::string('id', 36)->primary(),
                Field::string('ownerType', 16),
                Field::string('ownerId', 36),
                Field::string('organizationId', 36)->nullable(),
                Field::string('createdBy', 36),
                Field::string('name', 80),
                Field::string('environment', 8),
                Field::string('hint', 8),
                Field::string('keyHash', 128),
                Field::json('permissions'),
                Field::int('rateLimitWindow')->nullable(),
                Field::int('rateLimitMax')->nullable(),
                Field::json('metadata'),
                Field::string('rotatedFromId', 36)->nullable(),
                Field::datetime('graceUntil')->nullable(),
                Field::datetime('expiresAt')->nullable(),
                Field::datetime('lastUsedAt')->nullable(),
                Field::datetime('revokedAt')->nullable(),
                Field::datetime('createdAt'),
                Field::datetime('updatedAt'),
            ])->unique(['key_hash'], 'polaris_api_key_hash_unique')
                ->index(['owner_type', 'owner_id'], 'polaris_api_key_owner_index')
                ->index(['created_by'], 'polaris_api_key_creator_index'),
        ];
    }
}

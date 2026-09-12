<?php

declare(strict_types=1);

namespace Polaris\Scim;

use Polaris\Schema\Field;
use Polaris\Schema\Model;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Model\Provenance;
use Polaris\Scim\Model\Resource;

/**
 * The three tables the plugin owns.
 */
final class Schema
{
    public const string CONNECTIONS = 'polaris_scim_connection';
    public const string RESOURCES = 'polaris_scim_resource';
    public const string PROVENANCE = 'polaris_scim_membership_provenance';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::CONNECTIONS, Connection::class, [
                Field::string('id', 36)->primary(),
                Field::string('organizationId', 36),
                Field::string('ssoProviderId', 36)->nullable(),
                Field::string('name', 120),
                Field::string('tokenHash', 128),
                Field::string('status', 16),
                Field::json('settings'),
                Field::datetime('lastSyncAt')->nullable(),
                Field::datetime('decommissionedAt')->nullable(),
                Field::string('createdBy', 64)->nullable(),
                Field::datetime('createdAt'),
            ])->index(['organization_id'], 'polaris_scim_connection_org_index')->index(['token_hash'], 'polaris_scim_connection_token_index'),
            Model::table(self::RESOURCES, Resource::class, [
                Field::string('id', 36)->primary(),
                Field::string('connectionId', 36),
                Field::string('kind', 8),
                Field::string('externalId', 255),
                Field::string('localId', 36),
                Field::datetime('updatedAt'),
            ])->unique(['connection_id', 'kind', 'local_id'], 'polaris_scim_resource_unique'),
            Model::table(self::PROVENANCE, Provenance::class, [
                Field::string('id', 36)->primary(),
                Field::string('organizationId', 36),
                Field::string('userId', 36),
                Field::string('connectionId', 36),
                Field::datetime('createdAt'),
            ])->unique(['organization_id', 'user_id'], 'polaris_scim_provenance_unique'),
        ];
    }
}

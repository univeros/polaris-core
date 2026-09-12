<?php

declare(strict_types=1);

namespace Polaris\Sso;

use Polaris\Schema\Field;
use Polaris\Schema\Model;
use Polaris\Sso\Model\Domain;
use Polaris\Sso\Model\Provider;

/**
 * The two tables the plugin owns.
 */
final class Schema
{
    public const string PROVIDERS = 'polaris_sso_provider';
    public const string DOMAINS = 'polaris_sso_domain';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::PROVIDERS, Provider::class, [
                Field::string('id', 36)->primary(),
                Field::string('organizationId', 36),
                Field::string('type', 8),
                Field::string('name', 120),
                Field::string('issuer', 512),
                Field::json('config'),
                Field::json('attributes'),
                Field::json('jit'),
                Field::json('redirectUris'),
                Field::bool('enabled'),
                Field::string('createdBy', 64)->nullable(),
                Field::datetime('createdAt'),
                Field::datetime('updatedAt'),
            ])->index(['organization_id'], 'polaris_sso_provider_org_index'),
            Model::table(self::DOMAINS, Domain::class, [
                Field::string('id', 36)->primary(),
                Field::string('organizationId', 36),
                Field::string('providerId', 36),
                Field::string('domain', 253),
                Field::string('token', 64),
                Field::datetime('verifiedAt')->nullable(),
                Field::datetime('createdAt'),
            ])->unique(['domain'], 'polaris_sso_domain_unique')->index(['organization_id'], 'polaris_sso_domain_org_index'),
        ];
    }
}

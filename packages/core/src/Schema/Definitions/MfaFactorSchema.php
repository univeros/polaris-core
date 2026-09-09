<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\MfaFactor;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class MfaFactorSchema
{
    public static function define(): Model
    {
        return Model::table('auth_mfa_factors', MfaFactor::class, [
            Field::string('id', 36)->primary(),
            Field::string('userId', 36),
            Field::string('type', 16),
            Field::string('label', 80)->nullable(),
            Field::text('secretEncrypted')->nullable(),
            Field::string('phoneE164', 20)->nullable(),
            Field::string('email', 320)->nullable(),
            Field::bool('isDefault')->default(false),
            Field::datetime('confirmedAt')->nullable(),
            Field::datetime('lastUsedAt')->nullable(),
            Field::datetime('createdAt'),
            Field::datetime('updatedAt'),
        ])
            ->index(['user_id', 'type'], 'auth_mfa_factors_user_type_index')
            ->index(['user_id', 'confirmed_at'], 'auth_mfa_factors_user_confirmed_index');
    }
}

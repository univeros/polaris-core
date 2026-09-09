<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\RecoveryCode;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class RecoveryCodeSchema
{
    public static function define(): Model
    {
        return Model::table('auth_recovery_codes', RecoveryCode::class, [
            Field::string('id', 36)->primary(),
            Field::string('userId', 36),
            Field::string('codeHash', 64),
            Field::datetime('usedAt')->nullable(),
            Field::datetime('createdAt'),
        ])
            ->index(['user_id', 'used_at'], 'auth_recovery_codes_user_used_index');
    }
}

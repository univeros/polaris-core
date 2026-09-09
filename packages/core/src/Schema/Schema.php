<?php

declare(strict_types=1);

namespace Polaris\Schema;

use InvalidArgumentException;
use Polaris\Schema\Definitions\AuditLogEntrySchema;
use Polaris\Schema\Definitions\EmailVerificationSchema;
use Polaris\Schema\Definitions\InvitationSchema;
use Polaris\Schema\Definitions\MembershipSchema;
use Polaris\Schema\Definitions\MembershipRoleSchema;
use Polaris\Schema\Definitions\MfaFactorSchema;
use Polaris\Schema\Definitions\OrganizationSchema;
use Polaris\Schema\Definitions\OtpChallengeSchema;
use Polaris\Schema\Definitions\PasswordResetSchema;
use Polaris\Schema\Definitions\PermissionSchema;
use Polaris\Schema\Definitions\RecoveryCodeSchema;
use Polaris\Schema\Definitions\RefreshTokenSchema;
use Polaris\Schema\Definitions\RoleSchema;
use Polaris\Schema\Definitions\RolePermissionSchema;
use Polaris\Schema\Definitions\UserSchema;

use function sprintf;

/**
 * Every model Polaris stores, as data: the source of truth for the property/column mapping,
 * for the generic repository, and for `schema:export`.
 */
final class Schema
{
    /** @var list<Model>|null */
    private static ?array $all = null;

    /** @var array<class-string, Model> */
    private static array $byClass = [];

    /**
     * @return list<Model>
     */
    public static function all(): array
    {
        return self::$all ??= [
            AuditLogEntrySchema::define(),
            EmailVerificationSchema::define(),
            InvitationSchema::define(),
            MembershipSchema::define(),
            MembershipRoleSchema::define(),
            MfaFactorSchema::define(),
            OrganizationSchema::define(),
            OtpChallengeSchema::define(),
            PasswordResetSchema::define(),
            PermissionSchema::define(),
            RecoveryCodeSchema::define(),
            RefreshTokenSchema::define(),
            RoleSchema::define(),
            RolePermissionSchema::define(),
            UserSchema::define(),
        ];
    }

    /**
     * @param class-string $class
     */
    public static function for(string $class): Model
    {
        if (self::$byClass === []) {
            foreach (self::all() as $model) {
                self::$byClass[$model->class] = $model;
            }
        }

        return self::$byClass[$class] ?? throw new InvalidArgumentException(sprintf('No schema is defined for %s.', $class));
    }
}

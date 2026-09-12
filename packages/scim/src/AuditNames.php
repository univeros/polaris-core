<?php

declare(strict_types=1);

namespace Polaris\Scim;

/**
 * The `scim.*` names of the audit catalog.
 */
final class AuditNames
{
    public const string CONNECTION_CREATED = 'scim.connection_created';
    public const string CONNECTION_ROTATED = 'scim.connection_rotated';
    public const string CONNECTION_DECOMMISSIONED = 'scim.connection_decommissioned';
    public const string USER_CREATED = 'scim.user_created';
    public const string USER_UPDATED = 'scim.user_updated';
    public const string USER_DEACTIVATED = 'scim.user_deactivated';
    public const string USER_REACTIVATED = 'scim.user_reactivated';
    public const string USER_DELETED = 'scim.user_deleted';
    public const string GROUP_CREATED = 'scim.group_created';
    public const string GROUP_UPDATED = 'scim.group_updated';
    public const string GROUP_DELETED = 'scim.group_deleted';
    public const string REQUEST_REJECTED = 'scim.request_rejected';

    /** @var array<string, string> name => description */
    public const array ALL = [
        self::CONNECTION_CREATED => 'A SCIM connection was created for an organization',
        self::CONNECTION_ROTATED => 'A SCIM connection token was rotated',
        self::CONNECTION_DECOMMISSIONED => 'A SCIM connection was decommissioned',
        self::USER_CREATED => 'A directory provisioned a user',
        self::USER_UPDATED => 'A directory updated a user',
        self::USER_DEACTIVATED => 'A directory deactivated a user',
        self::USER_REACTIVATED => 'A directory reactivated a user',
        self::USER_DELETED => 'A directory deleted (anonymised) a user',
        self::GROUP_CREATED => 'A directory created a group (a role)',
        self::GROUP_UPDATED => 'A directory changed a group or its members',
        self::GROUP_DELETED => 'A directory deleted a group',
        self::REQUEST_REJECTED => 'A SCIM request was refused (reason)',
    ];
}

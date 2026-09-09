<?php

declare(strict_types=1);

namespace Polaris\Schema\Definitions;

use Polaris\Model\AuditLogEntry;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

final class AuditLogEntrySchema
{
    public static function define(): Model
    {
        return Model::table('auth_audit_log', AuditLogEntry::class, [
            Field::string('id', 36)->primary(),
            Field::string('actorUserId', 36)->nullable(),
            Field::string('organizationId', 36)->nullable(),
            Field::string('event', 80),
            Field::string('ip', 45)->nullable(),
            Field::string('userAgent', 255)->nullable(),
            Field::json('metadata'),
            Field::datetime('createdAt'),
        ])
            ->index(['actor_user_id', 'created_at'], 'auth_audit_log_actor_index')
            ->index(['organization_id', 'created_at'], 'auth_audit_log_org_index')
            ->index(['event', 'created_at'], 'auth_audit_log_event_index');
    }
}

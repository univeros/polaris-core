<?php

declare(strict_types=1);

namespace Polaris\Audit;

use Polaris\Audit\Model\Activity;
use Polaris\Audit\Model\AuditDrain;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The three tables the plugin owns.
 */
final class Schema
{
    public const string EVENTS = 'polaris_audit_event';
    public const string DRAINS = 'polaris_audit_drain';
    public const string ACTIVITY = 'polaris_audit_activity';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::EVENTS, AuditEvent::class, [
                Field::string('id', 36)->primary(),
                Field::string('name', 64),
                Field::datetime('occurredAt'),
                Field::string('actorType', 16),
                Field::string('actorId', 64)->nullable(),
                Field::string('subjectId', 64)->nullable(),
                Field::string('organizationId', 64)->nullable(),
                Field::string('sessionId', 64)->nullable(),
                Field::string('ip', 45)->nullable(),
                Field::text('userAgent')->nullable(),
                Field::json('data'),
                Field::string('requestId', 64)->nullable(),
                Field::string('prevHash', 64)->nullable(),
                Field::string('hash', 64)->nullable(),
            ])
                ->index(['name', 'occurred_at'], 'polaris_audit_event_name_index')
                ->index(['occurred_at'], 'polaris_audit_event_occurred_index')
                ->index(['actor_id', 'occurred_at'], 'polaris_audit_event_actor_index')
                ->index(['subject_id', 'occurred_at'], 'polaris_audit_event_subject_index')
                ->index(['organization_id', 'occurred_at'], 'polaris_audit_event_org_index'),
            Model::table(self::DRAINS, AuditDrain::class, [
                Field::string('id', 36)->primary(),
                Field::string('organizationId', 36),
                Field::string('type', 16),
                Field::string('endpoint', 2048),
                Field::text('secret'),
                Field::json('filter'),
                Field::string('status', 16),
                Field::datetime('lastDeliveryAt')->nullable(),
                Field::text('lastError')->nullable(),
                Field::datetime('createdAt'),
                Field::string('createdBy', 36)->nullable(),
            ])->index(['organization_id', 'status'], 'polaris_audit_drain_org_index'),
            Model::table(self::ACTIVITY, Activity::class, [
                Field::string('userId', 36)->primary(),
                Field::datetime('lastActiveAt'),
            ]),
        ];
    }
}

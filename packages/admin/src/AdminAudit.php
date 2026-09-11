<?php

declare(strict_types=1);

namespace Polaris\Admin;

use Polaris\Admin\Principal\Principal;
use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Recorder;
use Polaris\Token\ClientContext;
use Psr\Clock\ClockInterface;

/**
 * The `admin.*` names of the audit catalog and the one call that records an operator's action: the
 * principal is the actor (`admin` or `api_key`), the target the subject.
 */
final class AdminAudit
{
    public const string USER_BANNED = 'admin.user_banned';
    public const string USER_UNBANNED = 'admin.user_unbanned';
    public const string PASSWORD_SET = 'admin.password_set';
    public const string USER_DELETED = 'admin.user_deleted';
    public const string USER_IMPERSONATED = 'admin.user_impersonated';
    public const string SESSION_REVOKED = 'admin.session_revoked';
    public const string SESSIONS_REVOKED = 'admin.sessions_revoked';
    public const string MFA_FACTOR_REMOVED = 'admin.mfa_factor_removed';
    public const string MFA_RESET = 'admin.mfa_reset';
    public const string MEMBER_ROLES_CHANGED = 'admin.member_roles_changed';
    public const string ORGANIZATION_DELETED = 'admin.organization_deleted';
    public const string DRAIN_CREATED = 'admin.drain_created';
    public const string DRAIN_DELETED = 'admin.drain_deleted';
    public const string DRAIN_TESTED = 'admin.drain_tested';
    public const string KEY_CREATED = 'admin.key_created';
    public const string KEY_DELETED = 'admin.key_deleted';
    public const string GRANT_CREATED = 'admin.grant_created';
    public const string GRANT_DELETED = 'admin.grant_deleted';

    /** @var array<string, string> name => description */
    public const array NAMES = [
        self::USER_BANNED => 'An operator banned a user',
        self::USER_UNBANNED => 'An operator unbanned a user',
        self::PASSWORD_SET => 'An operator set a user\'s password',
        self::USER_DELETED => 'An operator deleted (anonymised) a user',
        self::USER_IMPERSONATED => 'An operator started impersonating a user',
        self::SESSION_REVOKED => 'An operator revoked a session',
        self::SESSIONS_REVOKED => 'An operator revoked every session of a user',
        self::MFA_FACTOR_REMOVED => 'An operator removed an MFA factor',
        self::MFA_RESET => 'An operator reset a user\'s MFA',
        self::MEMBER_ROLES_CHANGED => 'An operator changed a member\'s roles',
        self::ORGANIZATION_DELETED => 'An operator deleted an organization',
        self::DRAIN_CREATED => 'An operator created an audit drain',
        self::DRAIN_DELETED => 'An operator deleted an audit drain',
        self::DRAIN_TESTED => 'An operator tested an audit drain',
        self::KEY_CREATED => 'An operator created an API key',
        self::KEY_DELETED => 'An operator deleted an API key',
        self::GRANT_CREATED => 'An operator granted an admin role',
        self::GRANT_DELETED => 'An operator revoked an admin role',
    ];

    public function __construct(private readonly Recorder $recorder, private readonly ClockInterface $clock)
    {
    }

    /**
     * @param array<string, mixed> $data
     */
    public function record(string $name, Principal $actor, ?string $subjectId = null, ?string $organizationId = null, array $data = [], ?ClientContext $client = null): void
    {
        $this->recorder->record(AuditEvent::of(
            $name,
            $this->clock->now(),
            $actor->id,
            $actor->type === Principal::TYPE_API_KEY ? AuditEvent::ACTOR_API_KEY : AuditEvent::ACTOR_ADMIN,
            $subjectId,
            $organizationId,
            null,
            $client?->ip,
            $client?->userAgent,
            [...$data, 'actor_role' => $actor->role->value, 'actor_scope' => $actor->scope],
        ));
    }
}

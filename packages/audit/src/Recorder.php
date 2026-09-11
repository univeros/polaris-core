<?php

declare(strict_types=1);

namespace Polaris\Audit;

use Polaris\Audit\Model\AuditEvent;
use Polaris\Audit\Sink\AuditSink;
use Polaris\Event\MemberInvited;
use Polaris\Event\MemberJoined;
use Polaris\Event\MemberRemoved;
use Polaris\Event\MemberRolesChanged;
use Polaris\Event\MemberStatusChanged;
use Polaris\Event\MfaEnrolled;
use Polaris\Event\MfaFactorRemoved;
use Polaris\Event\MfaRecoveryRegenerated;
use Polaris\Event\MfaRecoveryUsed;
use Polaris\Event\MfaStepUpCompleted;
use Polaris\Event\MfaVerified;
use Polaris\Event\MfaVerifyFailed;
use Polaris\Event\OrganizationCreated;
use Polaris\Event\OrganizationDeleted;
use Polaris\Event\OrganizationSwitched;
use Polaris\Event\OrganizationUpdated;
use Polaris\Event\OtpChallengeSent;
use Polaris\Event\OtpVerifyFailed;
use Polaris\Event\PasswordChanged;
use Polaris\Event\PasswordResetRequested;
use Polaris\Event\RefreshReuseDetected;
use Polaris\Event\RoleCreated;
use Polaris\Event\RoleDeleted;
use Polaris\Event\RoleUpdated;
use Polaris\Event\SessionsRevoked;
use Polaris\Event\TokenRefreshed;
use Polaris\Event\UserDeleted;
use Polaris\Event\UserDisabled;
use Polaris\Event\UserEmailVerified;
use Polaris\Event\UserEnabled;
use Polaris\Event\UserLocked;
use Polaris\Event\UserLoggedIn;
use Polaris\Event\UserLoginFailed;
use Polaris\Event\UserRegistered;
use Psr\Clock\ClockInterface;

use const DATE_ATOM;

/**
 * The PSR-14 listener: every core event becomes a catalogued, redacted audit event and goes to the
 * sinks; an {@see Auditable} event of another package goes as it describes itself; anything else is
 * ignored. `record()` is the programmatic way for a package to emit one.
 */
final class Recorder
{
    public function __construct(
        private readonly Catalog $catalog,
        private readonly Redactor $redactor,
        private readonly AuditSink $sinks,
        private readonly ClockInterface $clock,
    ) {
    }

    public function __invoke(object $event): void
    {
        $audit = $event instanceof Auditable ? $event->toAuditEvent($this->clock) : $this->map($event);
        if ($audit !== null) {
            $this->record($audit);
        }
    }

    /**
     * Validates the name against the catalog, redacts the data, writes to every sink.
     */
    public function record(AuditEvent $event): void
    {
        $this->catalog->assert($event->name);
        $event->data = $this->redactor->redact($event->data);
        $this->sinks->write($event);
    }

    private function map(object $event): ?AuditEvent
    {
        $now = $this->clock->now();
        $user = fn(string $name, string $userId, array $data = [], ?string $ip = null, ?string $userAgent = null, ?string $sessionId = null): AuditEvent
            => AuditEvent::of($name, $now, $userId, AuditEvent::ACTOR_USER, $userId, null, $sessionId, $ip, $userAgent, $data);
        $admin = fn(string $name, ?string $actorId, string $subjectId, array $data = []): AuditEvent
            => AuditEvent::of($name, $now, $actorId, AuditEvent::ACTOR_USER, $subjectId, null, null, null, null, $data);
        $org = fn(string $name, ?string $actorId, string $organizationId, ?string $subjectId = null, array $data = []): AuditEvent
            => AuditEvent::of($name, $now, $actorId, AuditEvent::ACTOR_USER, $subjectId ?? $actorId, $organizationId, null, null, null, $data);

        return match (true) {
            $event instanceof UserRegistered => $user(Catalog::USER_SIGNED_UP, $event->userId, ['email' => $event->email]),
            $event instanceof UserEmailVerified => $user(Catalog::USER_EMAIL_VERIFIED, $event->userId, ['email' => $event->email]),
            $event instanceof UserLoggedIn => $user(Catalog::SESSION_SIGNED_IN, $event->userId, ['amr' => $event->amr], $event->ip, $event->userAgent, $event->sessionId),
            $event instanceof UserLoginFailed => $user(Catalog::SESSION_SIGN_IN_FAILED, $event->userId, ['reason' => $event->reason], $event->ip, $event->userAgent),
            $event instanceof UserLocked => $user(Catalog::USER_LOCKED, $event->userId, ['until' => $event->until?->format(DATE_ATOM)], $event->ip),
            $event instanceof PasswordChanged => $user(Catalog::PASSWORD_CHANGED, $event->userId, ['method' => $event->method]),
            $event instanceof PasswordResetRequested => $user(Catalog::PASSWORD_RESET_REQUESTED, $event->userId, ['email' => $event->email]),
            $event instanceof UserDisabled => $admin(Catalog::USER_DISABLED, $event->actorUserId, $event->userId),
            $event instanceof UserEnabled => $admin(Catalog::USER_ENABLED, $event->actorUserId, $event->userId),
            $event instanceof UserDeleted => $admin(Catalog::USER_DELETED, $event->actorUserId, $event->userId),
            $event instanceof TokenRefreshed => $user(Catalog::SESSION_ROTATED, $event->userId, ['family_id' => $event->familyId]),
            $event instanceof RefreshReuseDetected => $user(Catalog::SESSION_REUSE_DETECTED, $event->userId, ['family_id' => $event->familyId], $event->ip, $event->userAgent),
            $event instanceof SessionsRevoked => $user(Catalog::SESSION_REVOKED_ALL, $event->userId, ['count' => $event->count, 'reason' => $event->reason], $event->ip),
            $event instanceof OrganizationSwitched => $org(Catalog::SESSION_ORGANIZATION_SWITCHED, $event->userId, $event->toOrganizationId, $event->userId, ['from_organization_id' => $event->fromOrganizationId]),
            $event instanceof MfaEnrolled => $user(Catalog::MFA_ENABLED, $event->userId, ['factor_id' => $event->factorId, 'type' => $event->type]),
            $event instanceof MfaFactorRemoved => $user(Catalog::MFA_DISABLED, $event->userId, ['factor_id' => $event->factorId]),
            $event instanceof MfaVerified => $user(Catalog::MFA_CHALLENGE_PASSED, $event->userId, ['factor_id' => $event->factorId]),
            $event instanceof MfaVerifyFailed => $user(Catalog::MFA_CHALLENGE_FAILED, $event->userId, ['factor_id' => $event->factorId, 'type' => $event->type]),
            $event instanceof OtpVerifyFailed => $user(Catalog::MFA_CHALLENGE_FAILED, $event->userId, ['factor_id' => $event->factorId, 'attempts_left' => $event->attemptsLeft]),
            $event instanceof MfaStepUpCompleted => $user(Catalog::MFA_STEP_UP_COMPLETED, $event->userId, [], null, null, $event->sessionId),
            $event instanceof OtpChallengeSent => $user(Catalog::MFA_CODE_SENT, $event->userId, ['factor_id' => $event->factorId, 'channel' => $event->channel]),
            $event instanceof MfaRecoveryRegenerated => $user(Catalog::MFA_BACKUP_CODES_REGENERATED, $event->userId),
            $event instanceof MfaRecoveryUsed => $user(Catalog::MFA_BACKUP_CODE_USED, $event->userId, ['remaining' => $event->remaining]),
            $event instanceof OrganizationCreated => $org(Catalog::ORG_CREATED, $event->ownerUserId, $event->organizationId, null, ['slug' => $event->slug]),
            $event instanceof OrganizationUpdated => $org(Catalog::ORG_UPDATED, $event->actorUserId, $event->organizationId),
            $event instanceof OrganizationDeleted => $org(Catalog::ORG_DELETED, $event->actorUserId, $event->organizationId),
            $event instanceof RoleCreated => $org(Catalog::ORG_ROLE_CREATED, $event->actorUserId, $event->organizationId, null, ['role_id' => $event->roleId]),
            $event instanceof RoleUpdated => $org(Catalog::ORG_ROLE_UPDATED, $event->actorUserId, $event->organizationId, null, ['role_id' => $event->roleId]),
            $event instanceof RoleDeleted => $org(Catalog::ORG_ROLE_DELETED, $event->actorUserId, $event->organizationId, null, ['role_id' => $event->roleId]),
            $event instanceof MemberInvited => $org(Catalog::ORG_MEMBER_INVITED, $event->invitedBy, $event->organizationId, null, ['email' => $event->email]),
            $event instanceof MemberJoined => $org(Catalog::ORG_MEMBER_JOINED, $event->userId, $event->organizationId, $event->userId, ['email' => $event->email]),
            $event instanceof MemberRolesChanged => $org(Catalog::ORG_MEMBER_ROLES_CHANGED, $event->actorUserId, $event->organizationId, $event->userId, ['role_slugs' => $event->roleSlugs]),
            $event instanceof MemberStatusChanged => $org(Catalog::ORG_MEMBER_STATUS_CHANGED, $event->actorUserId, $event->organizationId, $event->userId, ['status' => $event->status]),
            $event instanceof MemberRemoved => $org(Catalog::ORG_MEMBER_REMOVED, $event->actorUserId, $event->organizationId, $event->userId),
            default => null,
        };
    }
}

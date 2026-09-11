<?php

declare(strict_types=1);

namespace Polaris\Audit;

use InvalidArgumentException;

use function array_keys;
use function preg_match;
use function sprintf;

/**
 * The closed list of event names an audit store accepts: dot-namespaced, past tense, each with a
 * description. Core's names are built in; a package extends the catalog at boot; an unknown name is
 * rejected at emit time, so dashboards and drains can trust the list.
 */
final class Catalog
{
    public const string USER_SIGNED_UP = 'user.signed_up';
    public const string USER_EMAIL_VERIFIED = 'user.email_verified';
    public const string USER_LOCKED = 'user.locked';
    public const string USER_DISABLED = 'user.disabled';
    public const string USER_ENABLED = 'user.enabled';
    public const string USER_DELETED = 'user.deleted';
    public const string SESSION_SIGNED_IN = 'session.signed_in';
    public const string SESSION_SIGN_IN_FAILED = 'session.sign_in_failed';
    public const string SESSION_ROTATED = 'session.rotated';
    public const string SESSION_REUSE_DETECTED = 'session.reuse_detected';
    public const string SESSION_REVOKED_ALL = 'session.revoked_all';
    public const string SESSION_ORGANIZATION_SWITCHED = 'session.organization_switched';
    public const string PASSWORD_CHANGED = 'password.changed';
    public const string PASSWORD_RESET_REQUESTED = 'password.reset_requested';
    public const string MFA_ENABLED = 'mfa.enabled';
    public const string MFA_DISABLED = 'mfa.disabled';
    public const string MFA_CHALLENGE_PASSED = 'mfa.challenge_passed';
    public const string MFA_CHALLENGE_FAILED = 'mfa.challenge_failed';
    public const string MFA_STEP_UP_COMPLETED = 'mfa.step_up_completed';
    public const string MFA_CODE_SENT = 'mfa.code_sent';
    public const string MFA_BACKUP_CODES_REGENERATED = 'mfa.backup_codes_regenerated';
    public const string MFA_BACKUP_CODE_USED = 'mfa.backup_code_used';
    public const string ORG_CREATED = 'org.created';
    public const string ORG_UPDATED = 'org.updated';
    public const string ORG_DELETED = 'org.deleted';
    public const string ORG_ROLE_CREATED = 'org.role_created';
    public const string ORG_ROLE_UPDATED = 'org.role_updated';
    public const string ORG_ROLE_DELETED = 'org.role_deleted';
    public const string ORG_MEMBER_INVITED = 'org.member_invited';
    public const string ORG_MEMBER_JOINED = 'org.member_joined';
    public const string ORG_MEMBER_ROLES_CHANGED = 'org.member_roles_changed';
    public const string ORG_MEMBER_STATUS_CHANGED = 'org.member_status_changed';
    public const string ORG_MEMBER_REMOVED = 'org.member_removed';
    public const string AUDIT_PRUNED = 'audit.pruned';

    /** @var array<string, string> name => description */
    private const array CORE = [
        self::USER_SIGNED_UP => 'A user registered',
        self::USER_EMAIL_VERIFIED => 'A user verified their email address',
        self::USER_LOCKED => 'A user was locked after repeated failed sign-ins',
        self::USER_DISABLED => 'An administrator disabled a user',
        self::USER_ENABLED => 'An administrator enabled a user',
        self::USER_DELETED => 'An administrator deleted a user',
        self::SESSION_SIGNED_IN => 'A user signed in',
        self::SESSION_SIGN_IN_FAILED => 'A sign-in failed',
        self::SESSION_ROTATED => 'A session rotated its refresh token',
        self::SESSION_REUSE_DETECTED => 'A refresh token was reused; the session family was revoked',
        self::SESSION_REVOKED_ALL => 'Every session of a user was revoked',
        self::SESSION_ORGANIZATION_SWITCHED => 'A session switched its active organization',
        self::PASSWORD_CHANGED => 'A password was changed',
        self::PASSWORD_RESET_REQUESTED => 'A password reset was requested',
        self::MFA_ENABLED => 'An MFA factor was enrolled',
        self::MFA_DISABLED => 'An MFA factor was removed',
        self::MFA_CHALLENGE_PASSED => 'An MFA challenge was passed',
        self::MFA_CHALLENGE_FAILED => 'An MFA challenge failed',
        self::MFA_STEP_UP_COMPLETED => 'A step-up authentication completed',
        self::MFA_CODE_SENT => 'A one-time code was sent',
        self::MFA_BACKUP_CODES_REGENERATED => 'The recovery codes were regenerated',
        self::MFA_BACKUP_CODE_USED => 'A recovery code was used',
        self::ORG_CREATED => 'An organization was created',
        self::ORG_UPDATED => 'An organization was updated',
        self::ORG_DELETED => 'An organization was deleted',
        self::ORG_ROLE_CREATED => 'A role was created',
        self::ORG_ROLE_UPDATED => 'A role was updated',
        self::ORG_ROLE_DELETED => 'A role was deleted',
        self::ORG_MEMBER_INVITED => 'A member was invited',
        self::ORG_MEMBER_JOINED => 'A member joined',
        self::ORG_MEMBER_ROLES_CHANGED => "A member's roles changed",
        self::ORG_MEMBER_STATUS_CHANGED => "A member's status changed",
        self::ORG_MEMBER_REMOVED => 'A member was removed',
        self::AUDIT_PRUNED => 'The retention policy pruned events (a hash-chain checkpoint)',
    ];

    /** @var array<string, string> */
    private array $names = self::CORE;

    /**
     * Registers a package's names (`<namespace>.<past_tense>`), once; a core name cannot be redefined.
     *
     * @param array<string, string> $names name => description
     */
    public function extend(array $names): void
    {
        foreach ($names as $name => $description) {
            if (preg_match('/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/', $name) !== 1) {
                throw new InvalidArgumentException(sprintf('"%s" is not a valid audit event name (namespace.past_tense).', $name));
            }
            if (isset(self::CORE[$name])) {
                throw new InvalidArgumentException(sprintf('"%s" is a core audit event and cannot be redefined.', $name));
            }
            $this->names[$name] = $description;
        }
    }

    public function has(string $name): bool
    {
        return isset($this->names[$name]);
    }

    public function assert(string $name): void
    {
        if (!$this->has($name)) {
            throw new InvalidArgumentException(sprintf('"%s" is not in the audit catalog; register it with Catalog::extend().', $name));
        }
    }

    /**
     * @return array<string, string> name => description, core first, then extensions in registration order
     */
    public function all(): array
    {
        return $this->names;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->names);
    }
}

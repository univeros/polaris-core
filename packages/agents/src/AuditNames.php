<?php

declare(strict_types=1);

namespace Polaris\Agents;

/**
 * The `agent.*` names the plugin adds to the audit catalog (spec §4.6).
 */
final class AuditNames
{
    public const string REGISTERED = 'agent.registered';
    public const string ENROLLED = 'agent.enrolled';
    public const string SUSPENDED = 'agent.suspended';
    public const string RESUMED = 'agent.resumed';
    public const string REVOKED = 'agent.revoked';
    public const string GRANT_REQUESTED = 'agent.grant.requested';
    public const string GRANT_APPROVED = 'agent.grant.approved';
    public const string GRANT_DENIED = 'agent.grant.denied';
    public const string GRANT_REVOKED = 'agent.grant.revoked';
    public const string GRANT_EXHAUSTED = 'agent.grant.exhausted';
    public const string EXECUTED = 'agent.executed';
    public const string EXECUTION_DENIED = 'agent.execution_denied';
    public const string RECEIPT_SEALED = 'agent.receipt.sealed';

    public const array ALL = [
        self::REGISTERED => 'An agent was registered by its owner (name, mode, auth, organization)',
        self::ENROLLED => 'A host enrolled an agent (host, name, mode, auth)',
        self::SUSPENDED => 'An agent was suspended',
        self::RESUMED => 'A suspended agent was resumed',
        self::REVOKED => 'An agent was revoked: its tokens, grants and approvals ended, its receipt chain sealed',
        self::GRANT_REQUESTED => 'An agent asked for capabilities (capabilities, approval method, user code, binding message)',
        self::GRANT_APPROVED => 'A capability grant was approved (capability, how, budget)',
        self::GRANT_DENIED => 'A capability grant was denied (capability)',
        self::GRANT_REVOKED => 'A capability grant was revoked (capability)',
        self::GRANT_EXHAUSTED => 'A capability grant spent its budget (capability)',
        self::EXECUTED => 'An agent executed a capability (capability, receipt, outcome)',
        self::EXECUTION_DENIED => 'An agent was refused an execution (capability, error)',
        self::RECEIPT_SEALED => 'An agent\'s receipt chain was sealed with a final receipt (receipt, seq)',
    ];
}

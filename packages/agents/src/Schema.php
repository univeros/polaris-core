<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Approval;
use Polaris\Agents\Model\Grant;
use Polaris\Agents\Model\Host;
use Polaris\Agents\Model\Receipt;
use Polaris\Schema\Field;
use Polaris\Schema\Model;

/**
 * The tables the plugin owns: the agents (each an OAuth client of polaris/oauth-provider, by the same
 * id), the hosts that enrol them, the capability grants with their budgets, the approvals a person
 * decides, and the receipt chain of every execution.
 */
final class Schema
{
    public const string AGENTS = 'polaris_agent';
    public const string HOSTS = 'polaris_agent_host';
    public const string GRANTS = 'polaris_agent_grant';
    public const string APPROVALS = 'polaris_agent_approval';
    public const string RECEIPTS = 'polaris_agent_receipt';

    /**
     * @return list<Model>
     */
    public static function models(): array
    {
        return [
            Model::table(self::AGENTS, Agent::class, [
                Field::string('id', 36)->primary(),
                Field::string('ownerType', 16),
                Field::string('ownerId', 36),
                Field::string('organizationId', 36)->nullable(),
                Field::string('name', 160),
                Field::string('mode', 16),
                Field::string('hostId', 36)->nullable(),
                Field::string('auth', 32),
                Field::json('publicJwk')->nullable(),
                Field::string('status', 16),
                Field::string('createdBy', 36),
                Field::datetime('sealedAt')->nullable(),
                Field::datetime('createdAt'),
                Field::datetime('updatedAt'),
            ])->index(['owner_type', 'owner_id'], 'polaris_agent_owner_index')
                ->index(['organization_id'], 'polaris_agent_org_index'),
            Model::table(self::HOSTS, Host::class, [
                Field::string('id', 36)->primary(),
                Field::string('ownerType', 16),
                Field::string('ownerId', 36),
                Field::string('organizationId', 36)->nullable(),
                Field::string('name', 160),
                Field::string('enrollmentTokenHash', 128),
                Field::json('defaultCapabilities'),
                Field::string('createdBy', 36),
                Field::datetime('revokedAt')->nullable(),
                Field::datetime('createdAt'),
            ])->unique(['enrollment_token_hash'], 'polaris_agent_host_token_unique')
                ->index(['owner_type', 'owner_id'], 'polaris_agent_host_owner_index'),
            Model::table(self::GRANTS, Grant::class, [
                Field::string('id', 36)->primary(),
                Field::string('agentId', 36),
                Field::string('capability', 80),
                Field::json('constraints'),
                Field::int('budgetTotal')->nullable(),
                Field::int('budgetRemaining')->nullable(),
                Field::string('budgetKind', 8)->nullable(),
                Field::string('budgetField', 80)->nullable(),
                Field::string('status', 16),
                Field::string('grantedBy', 36)->nullable(),
                Field::string('approvedVia', 32)->nullable(),
                Field::string('approvalId', 36)->nullable(),
                Field::datetime('expiresAt')->nullable(),
                Field::datetime('createdAt'),
                Field::datetime('updatedAt'),
            ])->index(['agent_id', 'capability', 'status'], 'polaris_agent_grant_lookup_index'),
            Model::table(self::APPROVALS, Approval::class, [
                Field::string('id', 36)->primary(),
                Field::string('agentId', 36),
                Field::json('grantIds'),
                Field::string('method', 32),
                Field::string('strength', 16),
                Field::string('userCode', 16),
                Field::string('bindingMessage', 160)->nullable(),
                Field::string('status', 16),
                Field::string('decidedBy', 36)->nullable(),
                Field::datetime('expiresAt'),
                Field::datetime('createdAt'),
                Field::datetime('updatedAt'),
            ])->index(['user_code', 'status'], 'polaris_agent_approval_code_index')
                ->index(['agent_id', 'status'], 'polaris_agent_approval_agent_index'),
            Model::table(self::RECEIPTS, Receipt::class, [
                Field::string('id', 36)->primary(),
                Field::string('agentId', 36),
                Field::int('seq'),
                Field::string('grantId', 36)->nullable(),
                Field::string('capability', 80)->nullable(),
                Field::string('inputHash', 64),
                Field::string('outcome', 16),
                Field::int('budgetBefore')->nullable(),
                Field::int('budgetAfter')->nullable(),
                Field::string('prevHash', 64)->nullable(),
                Field::string('hash', 64),
                Field::text('signature'),
                Field::datetime('createdAt'),
            ])->unique(['agent_id', 'seq'], 'polaris_agent_receipt_seq_unique'),
        ];
    }
}

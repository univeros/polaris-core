<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Approval;

/**
 * The discovery document, `GET /.well-known/agent-configuration` (`docs/better/agent-auth-compat.md`):
 * the provider, the issuer, the absolute endpoints under the mount, the modes, the approval methods
 * and strengths, the OAuth token endpoint, and the MCP endpoint when polaris/mcp is registered.
 */
final class Discovery
{
    public const string VERSION = '1.0-draft';
    public const array SDK_VERSIONS = ['@polaris-auth/agent' => '0.10.0', 'polaris/agent' => '0.10.0'];

    public function __construct(
        private readonly Settings $settings,
        private readonly string $issuer,
        private readonly string $tokenEndpoint,
        private readonly ?string $mcpEndpoint,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function document(): array
    {
        $url = $this->settings->url(...);
        $endpoints = [
            'register' => $url('/agents/register'),
            'enroll' => $url('/agents/enroll'),
            'capabilities' => $url('/agents/capabilities'),
            'execute' => $url('/agents/execute'),
            'request_capability' => $url('/agents/grants/request'),
            'status' => $url('/agents/session'),
            // The agent's id is appended: `POST /agents/{id}/revoke`.
            'revoke' => $url('/agents'),
            'grants' => $url('/agents/grants'),
            'approvals' => $url('/agents/approvals'),
            'receipts' => $url('/agents/receipts'),
            'token' => $this->tokenEndpoint,
        ];
        if ($this->mcpEndpoint !== null) {
            $endpoints['mcp'] = $this->mcpEndpoint;
        }

        return [
            'version' => self::VERSION,
            'provider_name' => $this->settings->providerName,
            'description' => $this->settings->description,
            'issuer' => $this->issuer,
            'default_location' => $endpoints['execute'],
            'algorithms' => AgentKeys::ALGORITHMS,
            'modes' => Agent::MODES,
            'approval_methods' => Approval::METHODS,
            'approval_strengths' => $this->settings->strengths,
            'endpoints' => $endpoints,
            'token_endpoint' => $this->tokenEndpoint,
            'agent_sdk_versions' => self::SDK_VERSIONS,
        ];
    }
}

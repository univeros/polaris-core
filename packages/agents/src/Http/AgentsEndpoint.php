<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Polaris\Agents\AgentAuthenticator;
use Polaris\Agents\AgentException;
use Polaris\Agents\Agents;
use Polaris\Agents\AuthenticatedAgent;
use Polaris\Agents\Model\Agent;
use Polaris\Authorization\Gate;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\Http\Message\ServerRequestInterface;

use function is_string;
use function trim;

/**
 * What every agents route shares: the `agents/*` problem documents, the owner a request acts as (the
 * caller, or an organization they may update), the agent a path names when the caller owns it, and the
 * agent the agent-facing routes authenticate themselves (an `auth: public` route, so core's delegation
 * rule never sees them; the request was handed over by the plugin's middleware).
 */
abstract class AgentsEndpoint extends Endpoint
{
    /** The permission a member needs to manage an organization's agents. */
    public const string ORGANIZATION_PERMISSION = PermissionCatalog::ORG_UPDATE;
    protected const array NO_STORE = ['Cache-Control' => 'no-store'];

    protected function refuse(AgentException $exception): Result
    {
        $headers = self::NO_STORE;
        if ($exception->status === 401) {
            // RFC 6750 §3.1: no error without a credential, `invalid_token` otherwise; the problem says which.
            $headers['WWW-Authenticate'] = $exception->type === AgentException::UNAUTHORIZED ? 'Bearer' : 'Bearer error="invalid_token"';
        }

        return new Result($exception->status, $exception->toProblem(), $headers, problem: true);
    }

    /**
     * The owner the request names: the caller (a user's agent, in their active organization), or the
     * organization `organization_id` names when it is the caller's active organization and they may
     * update it; checked here, not by `requires_permissions`, so the route stays a self-service write a
     * delegated credential cannot call.
     *
     * @return array{string, string, string|null} owner type, owner id, organization
     * @throws AgentException `forbidden`
     */
    protected function owner(Input $input, TokenInterface $token, Gate $gate): array
    {
        $organizationId = self::text($input, 'organization_id');
        if ($organizationId === null) {
            return [Agent::OWNER_USER, $this->actorId($token), $this->actorOrg($token)];
        }
        if ($organizationId !== $this->actorOrg($token) || !$gate->allows($token, self::ORGANIZATION_PERMISSION)) {
            throw new AgentException(AgentException::FORBIDDEN, 'Managing an organization\'s agents needs it as your active organization and the org.update permission in it.');
        }

        return [Agent::OWNER_ORGANIZATION, $organizationId, $organizationId];
    }

    /**
     * Whether the caller manages the agent: its owner, or a member who may update the organization that
     * owns it (their active one).
     */
    protected function manages(Agent $agent, TokenInterface $token, Gate $gate): bool
    {
        if ($agent->ownerType === Agent::OWNER_USER) {
            return $agent->ownerId === $this->actorId($token);
        }

        return $agent->ownerId === $this->actorOrg($token) && $gate->allows($token, self::ORGANIZATION_PERMISSION);
    }

    /**
     * The agent `{id}` names when the caller manages it.
     *
     * @throws AgentException `not_found`
     */
    protected function managed(Agents $agents, Input $input, TokenInterface $token, Gate $gate, string $field = 'id'): Agent
    {
        $agent = $agents->find((string) $input->get($field));
        if ($agent === null || !$this->manages($agent, $token, $gate)) {
            throw new AgentException(AgentException::NOT_FOUND, 'The agent does not exist.');
        }

        return $agent;
    }

    /**
     * The agents the caller manages: their own, and their active organization's when they may update it.
     *
     * @return list<Agent>
     */
    protected function managedAgents(Agents $agents, TokenInterface $token, Gate $gate): array
    {
        $list = $agents->forOwner(Agent::OWNER_USER, $this->actorId($token));
        $organizationId = $this->actorOrg($token);
        if ($organizationId !== null && $gate->allows($token, self::ORGANIZATION_PERMISSION)) {
            $list = [...$list, ...$agents->forOwner(Agent::OWNER_ORGANIZATION, $organizationId)];
        }

        return $list;
    }

    /**
     * The agent calling an agent-facing route.
     *
     * @throws AgentException `unauthorized`, `invalid_jwt`, `aud_mismatch`, `agent_inactive`
     */
    protected function agent(AgentAuthenticator $authenticator, Input $input): AuthenticatedAgent
    {
        $request = $input->attribute(AgentPrincipalMiddleware::REQUEST);
        if (!$request instanceof ServerRequestInterface) {
            throw new AgentException(AgentException::UNAUTHORIZED, 'The agents middleware did not run; register AgentsPlugin in Config::$plugins.');
        }

        return $authenticator->authenticate($request);
    }

    protected static function text(Input $input, string $field): ?string
    {
        $value = $input->get($field);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}

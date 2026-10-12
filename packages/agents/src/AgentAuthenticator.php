<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Closure;
use Polaris\Agents\Model\Agent;
use Polaris\Contract\BearerResolver;
use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\OAuth\Jwt;
use Polaris\OAuth\OAuthResolver;
use Polaris\OAuth\Tokens;
use Psr\Http\Message\ServerRequestInterface;

use function count;
use function is_string;
use function preg_match;

/**
 * Who the agent-facing routes (and `AgentRequestMiddleware`) talk to: an agent presenting a signed
 * request JWT ({@see RequestJwt}), or one of its OAuth access tokens (`at+jwt`, verified by the
 * provider's resolver, DPoP binding included) whose `client_id` is an agent. The agent must be active.
 */
final class AgentAuthenticator
{
    /** @var Closure(): BearerResolver */
    private readonly Closure $oauth;

    /**
     * @param callable(): BearerResolver $oauth the provider's bearer resolver, built when first needed
     */
    public function __construct(
        private readonly Agents $agents,
        private readonly RequestJwt $jwts,
        private readonly Capabilities $capabilities,
        callable $oauth,
    ) {
        $this->oauth = $oauth(...);
    }

    /**
     * @throws AgentException `unauthorized`, `invalid_jwt`, `aud_mismatch`, `agent_inactive`
     */
    public function authenticate(ServerRequestInterface $request): AuthenticatedAgent
    {
        if (preg_match('/^(Bearer|DPoP)\s+(\S+)$/i', $request->getHeaderLine('Authorization'), $matches) !== 1) {
            throw new AgentException(AgentException::UNAUTHORIZED, 'An agent credential is required: a signed request JWT or an access token as a bearer.');
        }
        $credential = $matches[2];
        $peeked = RequestJwt::peek($credential);
        if ($peeked !== null) {
            return $this->byJwt($credential, $peeked['sub'], $request);
        }
        $header = Jwt::header($credential);
        if ($header !== null && ($header['typ'] ?? null) === Tokens::TYP) {
            return $this->byToken($request);
        }
        throw new AgentException(AgentException::INVALID_JWT, 'The credential is neither an agent JWT (typ agent+jwt) nor an access token (typ at+jwt).');
    }

    /**
     * The agent behind a token core's pipeline already authenticated (an MCP call, a route after the
     * principal middleware), or null when the token is not an agent's. The token's subject must be the
     * agent (client credentials) or the agent's subject (an exchange of the owner's own session): the
     * exchange is open to any session, so anyone else's token naming the agent's client is refused
     * rather than driving the agent for its owner.
     *
     * @throws AgentException `agent_inactive`, `invalid_jwt`
     */
    public function fromToken(TokenInterface $token): ?AuthenticatedAgent
    {
        $clientId = $token->getMetadata(OAuthResolver::CLAIM_CLIENT);
        $agent = is_string($clientId) ? $this->agents->find($clientId) : null;
        if ($agent === null) {
            return null;
        }
        self::assertActive($agent);
        $subject = $token->getMetadata('sub');
        if ($subject !== $agent->id && $subject !== $agent->subject()) {
            throw new AgentException(AgentException::INVALID_JWT, 'The token\'s subject is neither the agent nor the user the agent acts for.');
        }

        return AuthenticatedAgent::viaToken($agent, $token);
    }

    /**
     * @throws AgentException `agent_inactive`
     */
    public static function assertActive(Agent $agent): void
    {
        if ($agent->isActive()) {
            return;
        }
        $error = $agent->status === Agent::STATUS_REVOKED ? 'agent_revoked' : 'agent_suspended';
        throw new AgentException(AgentException::AGENT_INACTIVE, 'The agent is ' . $agent->status . '.', $error);
    }

    /**
     * @throws AgentException
     */
    private function byJwt(string $jwt, string $sub, ServerRequestInterface $request): AuthenticatedAgent
    {
        $agent = $this->agents->find($sub);
        if ($agent === null) {
            throw new AgentException(AgentException::INVALID_JWT, 'sub does not name a registered agent.');
        }
        self::assertActive($agent);
        $verified = $this->jwts->verify($jwt, $agent, $request->getMethod(), (string) $request->getUri(), (string) $request->getBody());
        $capabilities = $verified['capabilities'];
        // A JWT for one capability's location may not open the door to several (compat: aud_mismatch).
        if ($capabilities !== null && count($capabilities) > 1 && $this->capabilities->atLocation((string) $request->getUri()) !== null) {
            throw new AgentException(AgentException::AUD_MISMATCH, 'A JWT listing several capabilities cannot use a capability location as its aud.');
        }

        return AuthenticatedAgent::viaJwt($agent, $capabilities);
    }

    /**
     * @throws AgentException
     */
    private function byToken(ServerRequestInterface $request): AuthenticatedAgent
    {
        try {
            $token = ($this->oauth)()->resolve($request);
        } catch (AuthorizationTokenException $exception) {
            throw new AgentException(AgentException::INVALID_JWT, 'The access token does not authenticate: ' . $exception->getMessage());
        }
        $principal = $token === null ? null : $this->fromToken($token);
        if ($principal === null) {
            throw new AgentException(AgentException::INVALID_JWT, 'The access token is not an agent\'s.');
        }

        return $principal;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\AgentAuthenticator;
use Polaris\Agents\AgentException;
use Polaris\Agents\Grants;
use Polaris\Agents\Model\Agent;
use Polaris\Authorization\Gate;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\OAuth\OAuthResolver;
use Polaris\Token\Token;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function array_intersect;
use function array_values;
use function in_array;
use function is_array;

/**
 * The agent principal on every Polaris route (after core's token authentication, before step-up and
 * authorization): a token whose `client_id` is an agent's is refused unless the agent is active and the
 * token's subject is the agent or the user it acts for ({@see AgentAuthenticator::fromToken()}), and
 * replaced in-process by one whose `delegated` permissions are the token's intersected with the
 * agent's live grants (so a revoked grant takes effect at the next request), with `actor_type: agent`,
 * `agent_id` and `act`; an autonomous agent's token (its own `sub`) acts as the agent's owner, in the
 * agent's organization, as an organization's API key does. On the routes tagged `agents`, the request
 * itself is handed to the endpoint, which authenticates the agent (an `auth: public` route).
 */
final class AgentPrincipalMiddleware implements MiddlewareInterface
{
    public const string TAG = 'agents';
    public const string REQUEST = 'polaris.agents.request';
    public const string ACTOR_TYPE = 'actor_type';
    public const string AGENT_ID = 'agent_id';

    public function __construct(
        private readonly AgentAuthenticator $authenticator,
        private readonly Grants $grants,
        private readonly Problems $problems,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if ($spec instanceof EndpointSpec && in_array(self::TAG, $spec->tags, true)) {
            $request = $request->withAttribute(self::REQUEST, $request);
        }
        $token = $request->getAttribute(Attributes::TOKEN);
        if (!$token instanceof TokenInterface) {
            return $handler->handle($request);
        }
        try {
            $principal = $this->authenticator->fromToken($token);
        } catch (AgentException $exception) {
            return $this->problems->respond($exception);
        }
        if ($principal === null) {
            return $handler->handle($request);
        }

        return $handler->handle($request->withAttribute(Attributes::TOKEN, $this->principal($token, $principal->agent)));
    }

    /**
     * The token as the rest of the pipeline sees it.
     */
    public function principal(TokenInterface $token, Agent $agent): TokenInterface
    {
        $metadata = (array) $token->getMetadata();
        $delegated = $metadata[Gate::DELEGATED] ?? [];
        $permissions = $this->grants->permissionsOf($agent);
        $metadata[Gate::DELEGATED] = is_array($delegated) ? array_values(array_intersect($delegated, $permissions)) : [];
        $metadata[self::ACTOR_TYPE] = 'agent';
        $metadata[self::AGENT_ID] = $agent->id;
        $metadata[OAuthResolver::CLAIM_ACT] = ['sub' => $agent->id, 'type' => 'agent'];
        if (($metadata['sub'] ?? null) === $agent->id) {
            // Client credentials: the agent acts as its owner, in its organization (an org's agent as the member who registered it).
            $metadata['sub'] = $agent->subject();
            $metadata['org'] = $agent->organizationId;
        }

        return new Token($token->getToken(), $metadata);
    }
}

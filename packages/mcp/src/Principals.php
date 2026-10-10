<?php

declare(strict_types=1);

namespace Polaris\Mcp;

use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Principal\Principals as Operators;
use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;

use function preg_match;
use function str_starts_with;

/**
 * Resolves the caller of the MCP server from a credential the way core's pipeline does: the plugins'
 * bearer resolvers first (an API key, an OAuth access token with a DPoP proof for the request), then
 * core's token factory for a session; and, when the admin plugin is registered, whether the credential
 * is an operator's (its principals: a `pak_` key, an admin grant, a superadmin session). A credential
 * nothing accepts is refused; none at all is the anonymous caller.
 */
final class Principals
{
    private const string OPERATOR_KEY_PREFIX = 'pak_';

    public function __construct(private readonly Graph $graph, private readonly ServerRequestFactoryInterface $requests, private readonly string $mcpUrl)
    {
    }

    /**
     * The caller behind a request's `Authorization` header (`Bearer` or `DPoP`).
     *
     * @throws McpException `unauthorized`
     */
    public function fromRequest(ServerRequestInterface $request): Principal
    {
        if (preg_match('/^(?:Bearer|DPoP)\s+(\S+)$/i', $request->getHeaderLine('Authorization'), $matches) !== 1) {
            return Principal::anonymous();
        }

        return $this->resolve($request, $matches[1]);
    }

    /**
     * The caller behind a bare credential (`bin/polaris mcp --token`): presented as a bearer on the
     * `/mcp` URL, so a DPoP-bound token (proven per request) cannot serve a stdio session.
     *
     * @throws McpException `unauthorized`
     */
    public function fromCredential(#[\SensitiveParameter] ?string $credential): Principal
    {
        if ($credential === null || $credential === '') {
            return Principal::anonymous();
        }

        return $this->resolve($this->requests->createServerRequest('POST', $this->mcpUrl)->withHeader('Authorization', 'Bearer ' . $credential), $credential);
    }

    /**
     * @throws McpException
     */
    private function resolve(ServerRequestInterface $request, #[\SensitiveParameter] string $credential): Principal
    {
        try {
            $token = $this->token($request, $credential);
        } catch (AuthorizationTokenException $exception) {
            throw new McpException(McpException::UNAUTHORIZED, 'The credential does not authenticate: ' . $exception->getMessage(), 401);
        }
        $operator = $this->operator($credential);
        if ($token === null && !$operator) {
            throw new McpException(McpException::UNAUTHORIZED, 'The credential is not one this server accepts.', 401);
        }

        return new Principal($token, $credential, $operator);
    }

    /**
     * @throws AuthorizationTokenException
     */
    private function token(ServerRequestInterface $request, #[\SensitiveParameter] string $credential): ?TokenInterface
    {
        foreach ($this->graph->bearerResolvers() as $resolver) {
            $token = $resolver->resolve($request);
            if ($token !== null) {
                return $token;
            }
        }
        if (str_starts_with($credential, self::OPERATOR_KEY_PREFIX)) {
            return null;
        }

        return $this->graph->tokenFactory()->fromTokenString($credential);
    }

    /**
     * The admin plugin, when registered, says whether the credential is an operator's; an impersonating
     * session is nobody's operator.
     */
    private function operator(#[\SensitiveParameter] string $credential): bool
    {
        if (!isset($this->graph->plugins()[AdminPlugin::ID])) {
            return false;
        }

        return $this->graph->get(Operators::class)->resolve($credential, null)->principal !== null;
    }
}

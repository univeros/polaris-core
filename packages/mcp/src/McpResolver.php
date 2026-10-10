<?php

declare(strict_types=1);

namespace Polaris\Mcp;

use Override;
use Polaris\Contract\BearerResolver;
use Polaris\Contract\TokenInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authenticates the in-process requests a tool call dispatches: the principal resolved once at `/mcp`
 * (or at `bin/polaris mcp`) travels as the request attribute {@see McpPlugin::PRINCIPAL}, never as a
 * header, so a DPoP-bound token proven for `/mcp` serves every inner call and nothing on the wire can
 * set it. Null for every other request.
 */
final class McpResolver implements BearerResolver
{
    #[Override]
    public function resolve(ServerRequestInterface $request): ?TokenInterface
    {
        $token = $request->getAttribute(McpPlugin::PRINCIPAL);

        return $token instanceof TokenInterface ? $token : null;
    }
}

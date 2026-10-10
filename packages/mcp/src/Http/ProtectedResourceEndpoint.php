<?php

declare(strict_types=1);

namespace Polaris\Mcp\Http;

use Override;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Mcp\Protect\McpProtectedResource;

/**
 * `GET /.well-known/oauth-protected-resource/mcp`: the RFC 9728 metadata of Polaris's own `/mcp`,
 * where a client sent to it by the `WWW-Authenticate` challenge finds the authorization server.
 */
final class ProtectedResourceEndpoint extends Endpoint
{
    public function __construct(private readonly McpProtectedResource $protected)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        return new Result(200, $this->protected->metadata(), ['Cache-Control' => 'public, max-age=3600']);
    }
}

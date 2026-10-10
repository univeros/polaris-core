<?php

declare(strict_types=1);

namespace Polaris\Mcp\Http;

use Override;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Mcp\McpException;
use Polaris\Mcp\Principals;
use Polaris\Mcp\Protect\McpProtectedResource;
use Polaris\Mcp\Server\McpServer;
use Polaris\Mcp\Transport\Http;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function implode;

/**
 * `POST /mcp`: the protected resource first (a token for this resource, bound as it must be, with the
 * scopes), then the principal behind it (the bearer resolvers; a token the resource accepts but no
 * resolver knows is refused with the same `resource_metadata` challenge), then the JSON-RPC message
 * through the HTTP transport with the tools that principal may call. The transport's PSR-7 response is
 * returned as it is.
 */
final class McpEndpoint extends Endpoint
{
    public function __construct(
        private readonly McpProtectedResource $protected,
        private readonly Principals $principals,
        private readonly McpServer $server,
        private readonly Http $transport,
    ) {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $request = $input->attribute(McpRequestMiddleware::REQUEST);
        if (!$request instanceof ServerRequestInterface) {
            return $this->problem(500, 'mcp/misconfigured', 'Misconfigured', 'The mcp plugin\'s request middleware did not run.');
        }
        $handler = new class ($this) implements RequestHandlerInterface {
            public function __construct(private readonly McpEndpoint $endpoint)
            {
            }

            #[Override]
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->endpoint->serve($request);
            }
        };

        return self::result($this->protected->process($request, $handler));
    }

    /**
     * The message, once the resource accepted the token.
     */
    public function serve(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $principal = $this->principals->fromRequest($request);
        } catch (McpException $exception) {
            return $this->protected->problem(new McpException($exception->name, $exception->detail, $exception->status, ['WWW-Authenticate' => 'Bearer error="invalid_token", resource_metadata="' . $this->protected->metadataUrl() . '"']));
        }

        return $this->transport->handle($this->server->builder($principal), $request);
    }

    private static function result(ResponseInterface $response): Result
    {
        $headers = [];
        foreach ($response->getHeaders() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }

        return new Result($response->getStatusCode(), [], $headers, raw: (string) $response->getBody());
    }
}

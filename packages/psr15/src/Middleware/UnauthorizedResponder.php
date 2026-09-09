<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The 401 every authentication middleware answers with: the 1.0 envelope plus `WWW-Authenticate`.
 */
final class UnauthorizedResponder
{
    public function __construct(private readonly ResponseFactoryInterface $responseFactory)
    {
    }

    public function respond(string $challenge = 'Bearer', string $code = 'unauthorized', string $message = 'Authentication is required.'): ResponseInterface
    {
        $response = $this->responseFactory->createResponse(401)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('WWW-Authenticate', $challenge);
        $response->getBody()->write(json_encode(['error' => $code, 'message' => $message], JSON_THROW_ON_ERROR));

        return $response;
    }
}

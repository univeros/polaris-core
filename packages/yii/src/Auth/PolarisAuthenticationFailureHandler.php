<?php

declare(strict_types=1);

namespace Polaris\Yii\Auth;

use Override;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * What a missing or invalid bearer answers on the application's routes: 401 in Polaris's envelope
 * (the method adds the `WWW-Authenticate: Bearer` challenge).
 */
final readonly class PolarisAuthenticationFailureHandler implements RequestHandlerInterface
{
    public function __construct(private ResponseFactoryInterface $responses)
    {
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $response = $this->responses->createResponse(401)->withHeader('Content-Type', 'application/json');
        $response->getBody()->write(json_encode(['error' => 'unauthorized', 'message' => 'Authentication is required.'], JSON_THROW_ON_ERROR));

        return $response;
    }
}

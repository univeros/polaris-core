<?php

declare(strict_types=1);

namespace PolarisDemo;

use Polaris\Yii\Auth\PolarisIdentity;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Auth\Middleware\Authentication;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * An application route behind the Polaris authentication method: the identity yiisoft/auth stored on
 * the request is a PolarisIdentity.
 */
final readonly class MeAction
{
    public function __construct(private ResponseFactoryInterface $responses)
    {
    }

    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        $identity = $request->getAttribute(Authentication::class);
        if (!$identity instanceof PolarisIdentity) {
            return $this->json(401, ['error' => 'unauthorized']);
        }

        return $this->json(200, ['id' => $identity->user->id, 'email' => $identity->user->email, 'organization' => $identity->claim('org'), 'roles' => $identity->claim('roles')]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function json(int $status, array $body): ResponseInterface
    {
        $response = $this->responses->createResponse($status)->withHeader('Content-Type', 'application/json');
        $response->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR));

        return $response;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use LogicException;
use Polaris\Agents\AgentException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

use function class_exists;
use function json_encode;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * The problem documents the middleware answers outside an endpoint, and the PSR-17 factory they are
 * built with: the host's (`Config::$responseFactory` or the plugin's `responses:`), or a common
 * implementation when it is installed.
 */
final class Problems
{
    /** @var list<class-string<ResponseFactoryInterface>> none is required; a host with another passes it */
    private const array KNOWN = [
        'HttpSoft\Message\ResponseFactory',
        'Laminas\Diactoros\ResponseFactory',
        'Nyholm\Psr7\Factory\Psr17Factory',
        'GuzzleHttp\Psr7\HttpFactory',
    ];

    public function __construct(private readonly ResponseFactoryInterface $responses)
    {
    }

    public static function discover(): ResponseFactoryInterface
    {
        foreach (self::KNOWN as $class) {
            if (class_exists($class)) {
                return new $class();
            }
        }
        throw new LogicException('No PSR-17 response factory found; pass one to AgentsPlugin (responses:).');
    }

    public function respond(AgentException $exception): ResponseInterface
    {
        $response = $this->responses->createResponse($exception->status)
            ->withHeader('Content-Type', 'application/problem+json')
            ->withHeader('Cache-Control', 'no-store');
        if ($exception->status === 401) {
            // RFC 6750 §3.1: no error without a credential, `invalid_token` for one that does not authenticate;
            // the problem document carries the precise code.
            $response = $response->withHeader('WWW-Authenticate', $exception->type === AgentException::UNAUTHORIZED ? 'Bearer' : 'Bearer error="invalid_token"');
        }
        $response->getBody()->write(json_encode($exception->toProblem(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

        return $response;
    }
}

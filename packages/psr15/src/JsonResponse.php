<?php

declare(strict_types=1);

namespace Polaris\Psr15;

use Polaris\Http\Result;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * Renders a {@see Result} or an error envelope as a JSON response. An empty body stays empty,
 * as the 1.0 responder did.
 */
final class JsonResponse
{
    public function __construct(private readonly ResponseFactoryInterface $factory)
    {
    }

    public function result(Result $result): ResponseInterface
    {
        $response = $this->factory->createResponse($result->status)->withHeader('Content-Type', $result->problem ? 'application/problem+json' : 'application/json');
        foreach ($result->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        if ($result->body !== []) {
            $response->getBody()->write(json_encode($result->body, JSON_THROW_ON_ERROR));
        }

        return $response;
    }

    /**
     * @param array<string, string> $headers
     */
    public function error(int $status, string $code, string $message, array $headers = []): ResponseInterface
    {
        return $this->body($status, ['error' => $code, 'message' => $message], $headers);
    }

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $headers
     */
    public function body(int $status, array $body, array $headers = []): ResponseInterface
    {
        $response = $this->factory->createResponse($status)->withHeader('Content-Type', 'application/json');
        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        $response->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR));

        return $response;
    }
}

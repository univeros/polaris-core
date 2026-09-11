<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Support;

use Laminas\Diactoros\Response;
use Override;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function is_callable;
use function json_encode;
use function strtok;

use const JSON_THROW_ON_ERROR;

/**
 * A PSR-18 client answering by URL (query stripped): a JSON-serialisable body, a raw string, or a
 * callable taking the request; 404 for the rest. Records every request.
 */
final class RoutingHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    /**
     * @param array<string, mixed> $routes url => body (array), string, [status, body], or callable(RequestInterface): ResponseInterface
     */
    public function __construct(private array $routes = [])
    {
    }

    public function on(string $url, mixed $answer): void
    {
        $this->routes[$url] = $answer;
    }

    #[Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        $url = (string) strtok((string) $request->getUri(), '?');
        $answer = $this->routes[$url] ?? [404, ''];
        if (is_callable($answer)) {
            return $answer($request);
        }
        [$status, $body] = is_array($answer) && isset($answer[0]) && is_int($answer[0]) ? $answer : [200, $answer];
        $response = new Response(status: $status, headers: ['Content-Type' => is_string($body) ? 'text/plain' : 'application/json']);
        $response->getBody()->write(is_string($body) ? $body : json_encode($body, JSON_THROW_ON_ERROR));
        $response->getBody()->rewind();

        return $response;
    }
}

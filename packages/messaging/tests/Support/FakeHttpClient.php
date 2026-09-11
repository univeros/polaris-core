<?php

declare(strict_types=1);

namespace Polaris\Messaging\Tests\Support;

use Laminas\Diactoros\Response;
use Override;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class FakeHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    public function __construct(private readonly int $status = 200, private readonly string $body = '{}')
    {
    }

    #[Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        $response = new Response(status: $this->status, headers: ['Content-Type' => 'application/json']);
        $response->getBody()->write($this->body);
        $response->getBody()->rewind();

        return $response;
    }
}

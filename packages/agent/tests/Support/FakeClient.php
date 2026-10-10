<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests\Support;

use Laminas\Diactoros\Response\JsonResponse;
use Override;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function array_key_last;
use function count;
use function min;

/** A PSR-18 client answering queued responses (the last one again when the queue runs out) and keeping every request. */
final class FakeClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];
    /** @var list<array{int, array<string, mixed>}> */
    private array $queue = [];

    /**
     * @param array<string, mixed> $body
     */
    public function answer(int $status, array $body): self
    {
        $this->queue[] = [$status, $body];

        return $this;
    }

    #[Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        [$status, $body] = $this->queue[min(count($this->requests) - 1, array_key_last($this->queue) ?? 0)] ?? [200, []];

        return new JsonResponse($body, $status, ['Content-Type' => $status >= 400 ? 'application/problem+json' : 'application/json']);
    }

    public function last(): RequestInterface
    {
        return $this->requests[array_key_last($this->requests) ?? 0];
    }
}

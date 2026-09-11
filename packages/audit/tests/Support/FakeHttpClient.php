<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests\Support;

use HttpSoft\Message\ResponseFactory;
use Override;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

use function array_shift;

/**
 * Answers the scripted statuses in order (an exception for `null`) and keeps every request.
 */
final class FakeHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    /**
     * @param list<int|null> $statuses
     */
    public function __construct(private array $statuses = [200])
    {
    }

    #[Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        $status = array_shift($this->statuses) ?? 200;
        if ($status === 0) {
            throw new class ('connection refused') extends RuntimeException implements ClientExceptionInterface {
            };
        }

        return (new ResponseFactory())->createResponse($status);
    }
}

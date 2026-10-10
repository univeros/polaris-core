<?php

declare(strict_types=1);

namespace Polaris\OAuth\Tests\Support;

use Laminas\Diactoros\Response;
use Override;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * A PSR-18 client answering recorded documents by URL: the client ID metadata documents and the
 * `jwks_uri` the tests publish. Unknown URLs answer 404.
 */
final class FakeHttp implements ClientInterface
{
    /** @var array<string, array{int, array<string, mixed>}> url => [status, json] */
    private array $documents = [];

    /** @var list<string> every URL fetched, in order */
    public array $fetched = [];

    /**
     * @param array<string, mixed> $document
     */
    public function publish(string $url, array $document, int $status = 200): void
    {
        $this->documents[$url] = [$status, $document];
    }

    #[Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $url = (string) $request->getUri();
        $this->fetched[] = $url;
        [$status, $document] = $this->documents[$url] ?? [404, ['error' => 'not_found']];
        $response = new Response('php://memory', $status, ['Content-Type' => 'application/json']);
        $response->getBody()->write(json_encode($document, JSON_THROW_ON_ERROR));
        $response->getBody()->rewind();

        return $response;
    }
}

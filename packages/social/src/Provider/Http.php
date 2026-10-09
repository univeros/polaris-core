<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use Polaris\Social\SocialException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

use function http_build_query;
use function is_array;
use function json_decode;
use function sprintf;
use function parse_str;
use function substr;

use const PHP_QUERY_RFC3986;

/**
 * The HTTP a provider needs, over the host's PSR-18 client and PSR-17 factories: a form POST and a GET
 * (or POST) with a bearer, both answering decoded JSON; a provider that answers a form-encoded body
 * (GitHub without the Accept header) is read too.
 */
final class Http
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
    ) {
    }

    /**
     * @param array<string, string> $form
     * @param array<string, string> $headers
     * @return array<string, mixed>
     * @throws SocialException
     */
    public function postForm(string $url, array $form, array $headers = []): array
    {
        $request = $this->requests->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streams->createStream(http_build_query($form, '', '&', PHP_QUERY_RFC3986)));
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $this->send($request, 'the token endpoint');
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, mixed>
     * @throws SocialException
     */
    public function json(string $method, string $url, ?string $bearer, array $headers = []): array
    {
        $request = $this->requests->createRequest($method, $url)->withHeader('Accept', 'application/json');
        if ($bearer !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $bearer);
        }
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $this->send($request, $url);
    }

    /**
     * @return array<string, mixed>
     * @throws SocialException
     */
    private function send(\Psr\Http\Message\RequestInterface $request, string $what): array
    {
        try {
            $response = $this->client->sendRequest($request);
        } catch (Throwable $exception) {
            throw new SocialException(SocialException::PROVIDER_ERROR, sprintf('%s could not be reached: %s', $what, $exception->getMessage()));
        }
        $body = (string) $response->getBody();
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            parse_str($body, $parsed);
            $decoded = $parsed;
        }
        if ($response->getStatusCode() >= 400) {
            $error = (string) ($decoded['error_description'] ?? $decoded['error'] ?? $decoded['message'] ?? '');
            throw new SocialException(SocialException::PROVIDER_ERROR, sprintf('%s answered HTTP %d%s', $what, $response->getStatusCode(), $error === '' ? '' : ': ' . substr($error, 0, 200)));
        }
        if ($decoded === []) {
            throw new SocialException(SocialException::PROVIDER_ERROR, sprintf('%s answered no JSON', $what));
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}

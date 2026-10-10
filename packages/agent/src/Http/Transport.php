<?php

declare(strict_types=1);

namespace Polaris\Agent\Http;

use Polaris\Agent\AgentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function http_build_query;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function sprintf;
use function substr;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * The SDK's HTTP calls over a PSR-18 client and PSR-17 factories: a JSON or form body sent exactly as
 * encoded (the request JWT hashes those bytes), the answer parsed, a non-2xx answer thrown as an
 * {@see AgentException} with its problem document.
 */
final class Transport
{
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
    ) {
    }

    /**
     * @param array<string, mixed> $body
     */
    public static function encode(array $body): string
    {
        return json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * @param array<string, mixed> $form
     */
    public static function encodeForm(array $form): string
    {
        return http_build_query($form);
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, mixed>
     * @throws AgentException
     */
    public function send(string $method, string $url, ?string $body, array $headers, string $contentType = 'application/json'): array
    {
        $request = $this->requests->createRequest($method, $url)->withHeader('Accept', 'application/json');
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }
        if ($body !== null) {
            $request = $request->withHeader('Content-Type', $contentType)->withBody($this->streams->createStream($body));
        }
        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $exception) {
            throw new AgentException(sprintf('%s %s failed: %s', $method, $url, $exception->getMessage()), 0, null, 'transport_failed');
        }

        return self::answer($method, $url, $response);
    }

    /**
     * @return array<string, mixed>
     * @throws AgentException
     */
    private static function answer(string $method, string $url, ResponseInterface $response): array
    {
        $status = $response->getStatusCode();
        $text = (string) $response->getBody();
        $decoded = $text === '' ? null : json_decode($text, true);
        $parsed = is_array($decoded) ? $decoded : null;
        if ($status < 200 || $status >= 300) {
            $problem = $parsed !== null && is_string($parsed['type'] ?? null) && is_string($parsed['error'] ?? null) ? $parsed : null;
            $detail = $problem['detail'] ?? ($parsed['message'] ?? substr($text, 0, 200));
            $error = is_string($parsed['error'] ?? null) ? $parsed['error'] : 'request_failed';
            throw new AgentException(sprintf('%s %s answered %d: %s', $method, $url, $status, is_string($detail) ? $detail : ''), $status, $problem, $error);
        }
        if ($parsed === null) {
            throw new AgentException(sprintf('%s %s did not answer JSON.', $method, $url), $status);
        }

        return $parsed;
    }
}

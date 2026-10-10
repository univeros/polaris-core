<?php

declare(strict_types=1);

namespace Polaris\Agent\Http;

use Override;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function array_shift;
use function explode;
use function file_get_contents;
use function implode;
use function preg_match;
use function stream_context_create;
use function trim;

/**
 * A PSR-18 client over PHP's HTTP stream wrapper, for an agent that has no HTTP client of its own
 * (a script, a demo): one request, the status and headers read back, no redirects followed. Any
 * PSR-18 client (Guzzle, Symfony's) does the same job with more control.
 */
final class StreamClient implements ClientInterface
{
    public function __construct(
        private readonly ResponseFactoryInterface $responses,
        private readonly StreamFactoryInterface $streams,
        private readonly float $timeout = 30.0,
    ) {
    }

    #[Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[] = $name . ': ' . implode(', ', $values);
        }
        $context = stream_context_create(['http' => [
            'method' => $request->getMethod(),
            'header' => implode("\r\n", $headers),
            'content' => (string) $request->getBody(),
            'ignore_errors' => true,
            'follow_location' => 0,
            'timeout' => $this->timeout,
        ]]);
        $body = @file_get_contents((string) $request->getUri(), false, $context);
        if ($body === false) {
            throw new TransportException('No response from ' . $request->getUri() . '.', $request);
        }
        $statusLine = (string) array_shift($http_response_header);
        $status = preg_match('~^HTTP/\S+\s+(\d{3})~', $statusLine, $match) === 1 ? (int) $match[1] : 0;
        if ($status === 0) {
            throw new TransportException('Malformed status line from ' . $request->getUri() . ': ' . $statusLine, $request);
        }
        $response = $this->responses->createResponse($status)->withBody($this->streams->createStream($body));
        foreach ($http_response_header as $line) {
            $parts = explode(':', $line, 2);
            if (isset($parts[1])) {
                $response = $response->withAddedHeader(trim($parts[0]), trim($parts[1]));
            }
        }

        return $response;
    }
}

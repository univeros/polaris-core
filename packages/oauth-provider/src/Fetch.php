<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

use function is_array;
use function json_decode;
use function strlen;

/**
 * The outbound HTTPS the provider does: a client's metadata document (CIMD) and a client's `jwks_uri`,
 * through the host's PSR-18 client, bounded in size, JSON only.
 */
final class Fetch
{
    private const int MAX_BYTES = 65536;

    public function __construct(private readonly ?ClientInterface $client, private readonly ?RequestFactoryInterface $requests)
    {
    }

    public function available(): bool
    {
        return $this->client !== null && $this->requests !== null;
    }

    /**
     * @return array<string, mixed>
     * @throws OAuthException with `$error`
     */
    public function json(string $url, string $error): array
    {
        if ($this->client === null || $this->requests === null) {
            throw new OAuthException($error, 'The server has no HTTP client to fetch ' . $url . ' with.', 400);
        }
        try {
            $response = $this->client->sendRequest($this->requests->createRequest('GET', $url)->withHeader('Accept', 'application/json'));
        } catch (ClientExceptionInterface $exception) {
            throw new OAuthException($error, 'Fetching ' . $url . ' failed: ' . $exception->getMessage(), 400);
        }
        $body = (string) $response->getBody();
        if ($response->getStatusCode() !== 200 || strlen($body) > self::MAX_BYTES) {
            throw new OAuthException($error, 'Fetching ' . $url . ' answered ' . $response->getStatusCode() . ' or a document too large.', 400);
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new OAuthException($error, $url . ' is not a JSON object.', 400);
        }

        return $decoded;
    }
}

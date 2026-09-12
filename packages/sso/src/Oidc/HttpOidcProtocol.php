<?php

declare(strict_types=1);

namespace Polaris\Sso\Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Override;
use Polaris\Sso\Identity;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\SsoException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use SensitiveParameter;
use Throwable;

use function hash;
use function http_build_query;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function rtrim;
use function sprintf;
use function str_contains;
use function strtolower;
use function trim;

/**
 * OpenID Connect over PSR-18: discovery (`<issuer>/.well-known/openid-configuration`, cached an hour),
 * the authorization code flow with PKCE, the token endpoint with `client_secret_post`, the id_token
 * verified against the provider's JWKS (RS256 and friends through firebase/php-jwt, a minute of leeway),
 * issuer, audience and nonce checked here.
 */
final class HttpOidcProtocol implements OidcProtocol
{
    private const int CACHE_TTL = 3600;
    private const int LEEWAY = 60;
    private const string DEFAULT_SCOPES = 'openid email profile';

    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        private readonly CacheInterface $cache,
    ) {
    }

    #[Override]
    public function authorizationUrl(Provider $provider, string $redirectUri, string $state, string $nonce, string $codeChallenge): string
    {
        $configuration = $this->discover($provider);
        $endpoint = $configuration['authorization_endpoint'];
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => (string) $provider->setting('client_id'),
            'redirect_uri' => $redirectUri,
            'scope' => $provider->setting('scopes') ?? self::DEFAULT_SCOPES,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . $query;
    }

    #[Override]
    public function exchange(Provider $provider, #[SensitiveParameter] ?string $clientSecret, string $code, string $redirectUri, string $codeVerifier, string $nonce): Identity
    {
        $configuration = $this->discover($provider);
        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => (string) $provider->setting('client_id'),
            'code_verifier' => $codeVerifier,
        ];
        if ($clientSecret !== null) {
            $form['client_secret'] = $clientSecret;
        }
        $request = $this->requests->createRequest('POST', $configuration['token_endpoint'])
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streams->createStream(http_build_query($form)));
        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $exception) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'token endpoint unreachable: ' . $exception->getMessage());
        }
        $body = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || !is_array($body)) {
            throw new SsoException(SsoException::ASSERTION_INVALID, sprintf('token endpoint answered %d', $response->getStatusCode()));
        }
        $idToken = $body['id_token'] ?? null;
        if (!is_string($idToken) || $idToken === '') {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'no id_token in the token response');
        }

        return $this->identity($provider, $this->claims($provider, $configuration, $idToken, $nonce));
    }

    #[Override]
    public function endSessionUrl(Provider $provider, ?string $postLogoutRedirectUri): ?string
    {
        try {
            $endpoint = $this->discover($provider)['end_session_endpoint'] ?? null;
        } catch (SsoException) {
            return null;
        }
        if (!is_string($endpoint) || $endpoint === '') {
            return null;
        }
        $query = http_build_query(['client_id' => (string) $provider->setting('client_id'), 'post_logout_redirect_uri' => $postLogoutRedirectUri]);

        return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . $query;
    }

    #[Override]
    public function check(Provider $provider): array
    {
        $problems = [];
        if ($provider->setting('client_id') === null) {
            $problems[] = 'client_id is not set';
        }
        try {
            $configuration = $this->discover($provider, fresh: true);
            $this->jwks($configuration, fresh: true);
        } catch (SsoException $exception) {
            $problems[] = $exception->detail;
        }

        return $problems;
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(Provider $provider, array $configuration, string $idToken, string $nonce): array
    {
        JWT::$leeway = self::LEEWAY;
        try {
            $claims = (array) JWT::decode($idToken, JWK::parseKeySet($this->jwks($configuration), 'RS256'));
        } catch (SsoException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'id_token rejected: ' . $exception->getMessage());
        }
        if (($claims['iss'] ?? null) !== $configuration['issuer']) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'id_token issuer mismatch');
        }
        $audience = $claims['aud'] ?? [];
        $audience = is_array($audience) ? $audience : [$audience];
        if (!in_array($provider->setting('client_id'), $audience, true)) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'id_token audience mismatch');
        }
        if (($claims['nonce'] ?? null) !== $nonce) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'id_token nonce mismatch');
        }

        return $claims;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function identity(Provider $provider, array $claims): Identity
    {
        $subject = $claims['sub'] ?? null;
        $email = $claims[$provider->attribute('email')] ?? null;
        if (!is_string($subject) || $subject === '' || !is_string($email) || !str_contains($email, '@')) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'id_token carries no subject or email');
        }
        $name = $claims[$provider->attribute('name')] ?? null;

        return new Identity($subject, strtolower(trim($email)), is_string($name) && $name !== '' ? $name : null, $claims);
    }

    /**
     * @return array{issuer: string, authorization_endpoint: string, token_endpoint: string, jwks_uri: string, end_session_endpoint?: string}
     */
    private function discover(Provider $provider, bool $fresh = false): array
    {
        $issuer = $provider->setting('issuer') ?? $provider->issuer;
        $key = 'polaris.sso.oidc.discovery.' . hash('xxh128', $issuer);
        $cached = $fresh ? null : $this->cache->get($key);
        if (is_array($cached)) {
            /** @var array{issuer: string, authorization_endpoint: string, token_endpoint: string, jwks_uri: string, end_session_endpoint?: string} $cached */
            return $cached;
        }
        $document = $this->json(rtrim($issuer, '/') . '/.well-known/openid-configuration', 'discovery');
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $required) {
            if (!is_string($document[$required] ?? null) || $document[$required] === '') {
                throw new SsoException(SsoException::ASSERTION_INVALID, sprintf('discovery document lacks %s', $required));
            }
        }
        /** @var array{issuer: string, authorization_endpoint: string, token_endpoint: string, jwks_uri: string, end_session_endpoint?: string} $document */
        $this->cache->set($key, $document, self::CACHE_TTL);

        return $document;
    }

    /**
     * @param array{jwks_uri: string} $configuration
     * @return array{keys: list<array<string, mixed>>}
     */
    private function jwks(array $configuration, bool $fresh = false): array
    {
        $key = 'polaris.sso.oidc.jwks.' . hash('xxh128', $configuration['jwks_uri']);
        $cached = $fresh ? null : $this->cache->get($key);
        if (is_array($cached) && isset($cached['keys'])) {
            /** @var array{keys: list<array<string, mixed>>} $cached */
            return $cached;
        }
        $document = $this->json($configuration['jwks_uri'], 'JWKS');
        if (!is_array($document['keys'] ?? null) || $document['keys'] === []) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'the JWKS carries no keys');
        }
        /** @var array{keys: list<array<string, mixed>>} $document */
        $this->cache->set($key, $document, self::CACHE_TTL);

        return $document;
    }

    /**
     * @return array<string, mixed>
     */
    private function json(string $url, string $what): array
    {
        try {
            $response = $this->client->sendRequest($this->requests->createRequest('GET', $url)->withHeader('Accept', 'application/json'));
        } catch (ClientExceptionInterface $exception) {
            throw new SsoException(SsoException::ASSERTION_INVALID, sprintf('%s unreachable: %s', $what, $exception->getMessage()));
        }
        $body = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || !is_array($body)) {
            throw new SsoException(SsoException::ASSERTION_INVALID, sprintf('%s answered %d', $what, $response->getStatusCode()));
        }

        return $body;
    }
}

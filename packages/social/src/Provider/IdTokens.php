<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Polaris\Social\SocialException;
use Psr\SimpleCache\CacheInterface;
use SensitiveParameter;
use Throwable;

use function hash;
use function hash_equals;
use function in_array;
use function is_array;
use function is_string;
use function preg_match;
use function rtrim;
use function str_starts_with;

/**
 * OpenID Connect id_tokens verified against the provider's key set: the keys come from `jwks_uri` or
 * the issuer's discovery document, cached an hour and fetched again once when a key is unknown; the
 * issuer (exact or a pattern), the audience and the nonce are checked, with a minute of leeway.
 */
final class IdTokens
{
    private const int LEEWAY = 60;
    private const int JWKS_TTL = 3600;
    private const array ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];

    public function __construct(private readonly Http $http, private readonly CacheInterface $cache)
    {
    }

    /**
     * The claims of a valid id_token.
     *
     * @return array<string, mixed>
     * @throws SocialException
     */
    public function verify(Definition $definition, string $clientId, #[SensitiveParameter] string $idToken, ?string $nonce): array
    {
        $claims = $this->decode($definition, $idToken);
        $issuer = (string) ($claims['iss'] ?? '');
        $expected = (string) $definition->issuer;
        $issuerOk = str_starts_with($expected, '#') ? preg_match($expected, $issuer) === 1 : $issuer === $expected || $issuer === rtrim($expected, '/');
        if (!$issuerOk) {
            throw new SocialException(SocialException::TOKEN_INVALID, 'the id_token issuer is not the provider\'s');
        }
        $audience = $claims['aud'] ?? null;
        if ($audience !== $clientId && !(is_array($audience) && in_array($clientId, $audience, true))) {
            throw new SocialException(SocialException::TOKEN_INVALID, 'the id_token is not for this client');
        }
        if ($nonce !== null) {
            $claimed = $claims['nonce'] ?? null;
            if (!is_string($claimed) || !hash_equals($nonce, $claimed)) {
                throw new SocialException(SocialException::TOKEN_INVALID, 'the id_token nonce does not match');
            }
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>
     * @throws SocialException
     */
    private function decode(Definition $definition, string $idToken): array
    {
        JWT::$leeway = self::LEEWAY;
        $jwksUri = $this->jwksUri($definition);
        foreach ([false, true] as $fresh) {
            try {
                $claims = (array) JWT::decode($idToken, JWK::parseKeySet($this->jwks($jwksUri, $fresh), 'RS256'));

                /** @var array<string, mixed> $claims */
                return $claims;
            } catch (Throwable $exception) {
                // An unknown key id may be a rotated key: fetch the set once more.
                if ($fresh || !str_contains($exception->getMessage(), 'kid')) {
                    throw new SocialException(SocialException::TOKEN_INVALID, 'the id_token does not verify: ' . $exception->getMessage());
                }
            }
        }

        throw new SocialException(SocialException::TOKEN_INVALID, 'the id_token does not verify');
    }

    /**
     * @throws SocialException
     */
    private function jwksUri(Definition $definition): string
    {
        if ($definition->jwksUri !== null) {
            return $definition->jwksUri;
        }
        $issuer = (string) $definition->issuer;
        $key = 'polaris.social.discovery.' . hash('xxh128', $issuer);
        $cached = $this->cache->get($key);
        if (is_string($cached)) {
            return $cached;
        }
        $document = $this->http->json('GET', rtrim($issuer, '/') . '/.well-known/openid-configuration', null);
        $uri = $document['jwks_uri'] ?? null;
        if (!is_string($uri) || $uri === '') {
            throw new SocialException(SocialException::PROVIDER_ERROR, 'the discovery document names no jwks_uri');
        }
        $this->cache->set($key, $uri, self::JWKS_TTL);

        return $uri;
    }

    /**
     * @return array<string, mixed>
     * @throws SocialException
     */
    private function jwks(string $uri, bool $fresh): array
    {
        $key = 'polaris.social.jwks.' . hash('xxh128', $uri);
        if (!$fresh) {
            $cached = $this->cache->get($key);
            if (is_array($cached)) {
                /** @var array<string, mixed> $cached */
                return $cached;
            }
        }
        $document = $this->http->json('GET', $uri, null);
        if (!is_array($document['keys'] ?? null) || $document['keys'] === []) {
            throw new SocialException(SocialException::PROVIDER_ERROR, 'the key set carries no keys');
        }
        $this->cache->set($key, $document, self::JWKS_TTL);

        return $document;
    }

    /**
     * @return list<string>
     */
    public static function algorithms(): array
    {
        return self::ALGORITHMS;
    }
}

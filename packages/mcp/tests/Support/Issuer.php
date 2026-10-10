<?php

declare(strict_types=1);

namespace Polaris\Mcp\Tests\Support;

use Firebase\JWT\JWT;
use Polaris\Mcp\Jose;
use Polaris\Tests\Support\TestKeys;
use RuntimeException;

use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function time;

/**
 * A test issuer: mints access tokens with the suite's RSA key (`kid` test) or its alternate (a
 * stranger's), and publishes the key as a JWK Set, as a remote issuer's `jwks_uri` would.
 */
final class Issuer
{
    public const string KID = 'test';
    public const string URL = 'https://issuer.polaris.test';
    public const string JWKS = 'https://issuer.polaris.test/.well-known/jwks.json';

    /** @var array{private: string, public: string} */
    private readonly array $keys;

    public function __construct(bool $alternate = false)
    {
        $this->keys = $alternate ? TestKeys::rsaAlternate() : TestKeys::rsa();
    }

    public function publicKey(): string
    {
        return $this->keys['public'];
    }

    /**
     * @param array<string, mixed> $claims overriding the defaults (`iss`, `aud`, `exp`, `iat`, `nbf`, `sub`, `scope`)
     * @param array<string, string> $headers
     */
    public function token(array $claims = [], array $headers = [], string $kid = self::KID): string
    {
        $now = time();
        $payload = ['iss' => self::URL, 'sub' => 'ada', 'aud' => 'https://mcp.polaris.test/mcp', 'iat' => $now, 'nbf' => $now, 'exp' => $now + 600, 'jti' => 'jti-' . $now, 'scope' => 'org.read', ...$claims];

        return JWT::encode($payload, $this->keys['private'], 'RS256', $kid, ['typ' => 'at+jwt', ...$headers]);
    }

    /**
     * @return array{keys: list<array<string, string>>}
     */
    public function jwks(string $kid = self::KID): array
    {
        $key = openssl_pkey_get_private($this->keys['private']);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false || !isset($details['rsa'])) {
            throw new RuntimeException('Could not read the RSA key.');
        }

        return ['keys' => [[
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => Jose::base64UrlEncode((string) $details['rsa']['n']),
            'e' => Jose::base64UrlEncode((string) $details['rsa']['e']),
        ]]];
    }
}

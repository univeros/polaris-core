<?php

declare(strict_types=1);

namespace Polaris\OAuth\Tests\Support;

use Firebase\JWT\JWT as FirebaseJwt;
use Polaris\OAuth\Jwt;
use Polaris\Tests\Support\TestKeys;
use RuntimeException;

use function hash;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_new;
use function random_bytes;
use function time;
use function str_pad;

use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

/**
 * What a client needs in the tests: a P-256 key for DPoP proofs (and its public JWK), an RSA key for
 * `private_key_jwt` assertions (and its JWK Set), and PKCE pairs.
 */
final class Keys
{
    private string $ecPem;
    /** @var array<string, string> */
    private array $ecJwk;
    private string $rsaPem;
    /** @var array{keys: list<array<string, string>>} */
    private array $rsaJwks;
    public int $counter = 0;

    /**
     * @param bool $alternate the client's RSA key: the test suite's alternate key, or (false) its primary one, so two instances hold different keys
     */
    public function __construct(bool $alternate = true)
    {
        $ec = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        if ($ec === false || !openssl_pkey_export($ec, $pem)) {
            throw new RuntimeException('Could not generate an EC key.');
        }
        $this->ecPem = (string) $pem;
        $details = openssl_pkey_get_details($ec);
        if ($details === false || !isset($details['ec'])) {
            throw new RuntimeException('Could not read the EC key.');
        }
        $this->ecJwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => Jwt::base64UrlEncode(str_pad((string) $details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => Jwt::base64UrlEncode(str_pad((string) $details['ec']['y'], 32, "\0", STR_PAD_LEFT)),
        ];
        $rsa = $alternate ? TestKeys::rsaAlternate() : TestKeys::rsa();
        $this->rsaPem = $rsa['private'];
        $public = openssl_pkey_get_private($this->rsaPem);
        $rsaDetails = $public === false ? false : openssl_pkey_get_details($public);
        if ($rsaDetails === false || !isset($rsaDetails['rsa'])) {
            throw new RuntimeException('Could not read the RSA key.');
        }
        $this->rsaJwks = ['keys' => [[
            'kty' => 'RSA',
            'kid' => 'client-1',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => Jwt::base64UrlEncode((string) $rsaDetails['rsa']['n']),
            'e' => Jwt::base64UrlEncode((string) $rsaDetails['rsa']['e']),
        ]]];
    }

    /**
     * @return array<string, string>
     */
    public function dpopJwk(): array
    {
        return $this->ecJwk;
    }

    public function dpopThumbprint(): string
    {
        return Jwt::thumbprint($this->ecJwk);
    }

    /**
     * A DPoP proof for the method and URL (and the access token when given); `$jti` fixed to replay one.
     */
    public function dpopProof(string $method, string $url, ?string $accessToken = null, ?string $jti = null, ?int $iat = null): string
    {
        $claims = ['jti' => $jti ?? Jwt::base64UrlEncode(random_bytes(16)), 'htm' => $method, 'htu' => $url, 'iat' => $iat ?? time()];
        if ($accessToken !== null) {
            $claims['ath'] = Jwt::base64UrlEncode(hash('sha256', $accessToken, true));
        }

        return FirebaseJwt::encode($claims, $this->ecPem, 'ES256', null, ['typ' => 'dpop+jwt', 'jwk' => $this->ecJwk]);
    }

    /**
     * @return array{keys: list<array<string, string>>}
     */
    public function clientJwks(): array
    {
        return $this->rsaJwks;
    }

    /**
     * A `private_key_jwt` client assertion.
     */
    public function clientAssertion(string $clientId, string $audience, ?string $jti = null, ?int $exp = null): string
    {
        return FirebaseJwt::encode(['iss' => $clientId, 'sub' => $clientId, 'aud' => $audience, 'jti' => $jti ?? Jwt::base64UrlEncode(random_bytes(16)), 'iat' => time(), 'exp' => $exp ?? time() + 300], $this->rsaPem, 'RS256', 'client-1');
    }

    /**
     * @return array{string, string} the verifier and its S256 challenge
     */
    public static function pkce(): array
    {
        $verifier = Jwt::base64UrlEncode(random_bytes(32));

        return [$verifier, Jwt::base64UrlEncode(hash('sha256', $verifier, true))];
    }
}

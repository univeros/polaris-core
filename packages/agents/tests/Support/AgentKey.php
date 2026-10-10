<?php

declare(strict_types=1);

namespace Polaris\Agents\Tests\Support;

use Firebase\JWT\JWT as FirebaseJwt;
use Polaris\OAuth\Jwt;
use RuntimeException;

use function base64_encode;
use function hash;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function random_bytes;
use function sodium_crypto_sign_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;
use function str_pad;
use function time;

use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

/**
 * What an agent needs in the tests: a P-256 key (`ES256`) or an Ed25519 one (`EdDSA`), its public JWK,
 * signed request JWTs (`agent+jwt`) and `private_key_jwt` client assertions.
 */
final class AgentKey
{
    private string $privateKey;
    /** @var array<string, string> */
    private array $jwk;

    public function __construct(public readonly string $alg = 'ES256')
    {
        $b64 = Jwt::base64UrlEncode(...);
        if ($alg === 'EdDSA') {
            $pair = sodium_crypto_sign_keypair();
            $this->privateKey = base64_encode(sodium_crypto_sign_secretkey($pair));
            $this->jwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $b64(sodium_crypto_sign_publickey($pair))];

            return;
        }
        $ec = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $details = $ec === false ? false : openssl_pkey_get_details($ec);
        if ($ec === false || $details === false || !isset($details['ec']) || !openssl_pkey_export($ec, $pem)) {
            throw new RuntimeException('Could not generate an EC key.');
        }
        $this->privateKey = (string) $pem;
        $this->jwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $b64(str_pad((string) $details['ec']['x'], 32, "\0", STR_PAD_LEFT)), 'y' => $b64(str_pad((string) $details['ec']['y'], 32, "\0", STR_PAD_LEFT))];
    }

    /**
     * @return array<string, string>
     */
    public function jwk(): array
    {
        return $this->jwk;
    }

    public function kid(): string
    {
        return Jwt::thumbprint($this->jwk);
    }

    /**
     * A request JWT for the URL; `$claims` override or add (`capabilities`, `htm`, `htu`, `body_hash`,
     * `jti`, `iat`, `exp`, `aud`); `$headers` override the header (`typ`, `jku`).
     *
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public function requestJwt(string $agentId, string $url, array $claims = [], array $headers = [], ?int $now = null): string
    {
        $now ??= time();
        $payload = ['sub' => $agentId, 'aud' => $url, 'iat' => $now, 'exp' => $now + 120, 'jti' => Jwt::base64UrlEncode(random_bytes(16)), ...$claims];

        return FirebaseJwt::encode($payload, $this->privateKey, $this->alg, null, ['typ' => 'agent+jwt', ...$headers]);
    }

    /**
     * A `private_key_jwt` assertion for the token endpoint, signed with the agent's key and `kid`.
     */
    public function assertion(string $agentId, string $audience): string
    {
        $now = time();

        return FirebaseJwt::encode(['iss' => $agentId, 'sub' => $agentId, 'aud' => $audience, 'jti' => Jwt::base64UrlEncode(random_bytes(16)), 'iat' => $now, 'exp' => $now + 300], $this->privateKey, $this->alg, $this->kid());
    }

    public static function bodyHash(string $body): string
    {
        return Jwt::base64UrlEncode(hash('sha256', $body, true));
    }
}

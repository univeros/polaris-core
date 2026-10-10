<?php

declare(strict_types=1);

namespace Polaris\Agent;

use Firebase\JWT\JWT;
use InvalidArgumentException;
use RuntimeException;

use function base64_decode;
use function base64_encode;
use function hash;
use function is_string;
use function json_encode;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_new;
use function rtrim;
use function sodium_crypto_sign_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_publickey_from_secretkey;
use function sodium_crypto_sign_secretkey;
use function str_pad;
use function strtr;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const OPENSSL_KEYTYPE_EC;
use const STR_PAD_LEFT;

/**
 * An agent's key pair: a P-256 key through openssl (`ES256`) or an Ed25519 one through sodium (`EdDSA`).
 * The private part stays here and signs the request JWTs and `private_key_jwt` assertions; the public
 * JWK, with `kid` (the RFC 7638 thumbprint unless given) and `alg`, goes to Polaris at registration.
 */
final class AgentKey
{
    public const string ES256 = 'ES256';
    public const string EDDSA = 'EdDSA';

    /**
     * @param string $secret the PEM private key (ES256) or the base64 sodium secret key (EdDSA)
     * @param array<string, string> $publicJwk
     */
    private function __construct(
        public readonly string $alg,
        public readonly string $kid,
        private readonly string $secret,
        public readonly array $publicJwk,
    ) {
    }

    public static function generate(string $alg = self::ES256, ?string $kid = null): self
    {
        if ($alg === self::EDDSA) {
            $pair = sodium_crypto_sign_keypair();

            return self::fromParts($alg, base64_encode(sodium_crypto_sign_secretkey($pair)), ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::base64Url(sodium_crypto_sign_publickey($pair))], $kid);
        }
        if ($alg !== self::ES256) {
            throw new InvalidArgumentException('alg is ES256 or EdDSA.');
        }
        $ec = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        if ($ec === false || !openssl_pkey_export($ec, $pem)) {
            throw new RuntimeException('openssl could not generate a P-256 key.');
        }

        return self::fromPem((string) $pem, $kid);
    }

    /** An ES256 key from its PEM private key. */
    public static function fromPem(string $pem, ?string $kid = null): self
    {
        $key = openssl_pkey_get_private($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false || !isset($details['ec']['x'], $details['ec']['y']) || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            throw new InvalidArgumentException('The PEM is not a P-256 private key.');
        }
        $coordinate = static fn(string $bytes): string => self::base64Url(str_pad($bytes, 32, "\0", STR_PAD_LEFT));

        return self::fromParts(self::ES256, $pem, ['kty' => 'EC', 'crv' => 'P-256', 'x' => $coordinate((string) $details['ec']['x']), 'y' => $coordinate((string) $details['ec']['y'])], $kid);
    }

    /** An EdDSA key from its sodium secret key (64 bytes, raw). */
    public static function fromSodiumSecretKey(string $secretKey, ?string $kid = null): self
    {
        return self::fromParts(self::EDDSA, base64_encode($secretKey), ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::base64Url(sodium_crypto_sign_publickey_from_secretkey($secretKey))], $kid);
    }

    /**
     * The key as `toArray()` stored it.
     *
     * @param array<string, mixed> $stored
     */
    public static function fromArray(array $stored): self
    {
        $alg = $stored['alg'] ?? null;
        $secret = $stored['secret'] ?? null;
        $kid = $stored['kid'] ?? null;
        if (!is_string($alg) || !is_string($secret) || ($kid !== null && !is_string($kid))) {
            throw new InvalidArgumentException('A stored key has alg, secret and an optional kid.');
        }

        return $alg === self::EDDSA ? self::fromSodiumSecretKey((string) base64_decode($secret, true), $kid) : self::fromPem($secret, $kid);
    }

    /**
     * The key for the agent's own storage: `alg`, `kid`, `secret` (the PEM, or the base64 sodium secret key) and the public JWK.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return ['alg' => $this->alg, 'kid' => $this->kid, 'secret' => $this->secret, 'jwk' => $this->publicJwk];
    }

    /**
     * A compact JWS over the claims, signed with this key: `alg`, `kid` and the given headers (`typ`).
     *
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public function sign(array $claims, array $headers = []): string
    {
        return JWT::encode($claims, $this->secret, $this->alg, $this->kid, $headers);
    }

    /**
     * The RFC 7638 thumbprint of a public JWK (SHA-256, base64url).
     *
     * @param array<string, mixed> $jwk
     */
    public static function thumbprint(array $jwk): string
    {
        $members = match ($jwk['kty'] ?? null) {
            'EC' => ['crv', 'kty', 'x', 'y'],
            'OKP' => ['crv', 'kty', 'x'],
            'RSA' => ['e', 'kty', 'n'],
            default => throw new InvalidArgumentException('No thumbprint for this key type.'),
        };
        $canonical = [];
        foreach ($members as $member) {
            if (!is_string($jwk[$member] ?? null)) {
                throw new InvalidArgumentException('The key is missing ' . $member . '.');
            }
            $canonical[$member] = $jwk[$member];
        }

        return self::base64Url(hash('sha256', json_encode($canonical, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), true));
    }

    public static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @param array<string, string> $public
     */
    private static function fromParts(string $alg, string $secret, array $public, ?string $kid): self
    {
        $kid ??= self::thumbprint($public);

        return new self($alg, $kid, $secret, [...$public, 'alg' => $alg, 'kid' => $kid, 'use' => 'sig']);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\OAuth\Jwt;
use Polaris\OAuth\OAuthException;

use function is_array;
use function is_string;
use function preg_match;

/**
 * An agent's public key: an EC P-256 JWK (`ES256`) or an OKP Ed25519 one (`EdDSA`), the public part
 * only, with the `alg` it signs with and a `kid` (the agent's, or the RFC 7638 thumbprint) so the same
 * JWK serves `private_key_jwt` assertions at the token endpoint and the request JWTs.
 */
final class AgentKeys
{
    public const string ES256 = 'ES256';
    public const string EDDSA = 'EdDSA';
    public const array ALGORITHMS = [self::ES256, self::EDDSA];

    private function __construct()
    {
    }

    /**
     * @return array<string, mixed>
     * @throws AgentException `invalid_input`
     */
    public static function publicJwk(mixed $jwk): array
    {
        if (!is_array($jwk)) {
            throw new AgentException(AgentException::INVALID_INPUT, 'jwk is required for private_key_jwt: the agent\'s public key as a JWK (EC P-256 or OKP Ed25519).');
        }
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as $private) {
            if (isset($jwk[$private])) {
                throw new AgentException(AgentException::INVALID_INPUT, 'jwk must be the public part of the key only.');
            }
        }
        $alg = self::algorithmOf($jwk);
        if ($alg === null) {
            throw new AgentException(AgentException::INVALID_INPUT, 'jwk is an EC key on P-256 (x, y) or an OKP key on Ed25519 (x).');
        }
        foreach (['x', 'y'] as $coordinate) {
            if (isset($jwk[$coordinate]) && (!is_string($jwk[$coordinate]) || preg_match('/^[A-Za-z0-9_-]{32,128}$/', $jwk[$coordinate]) !== 1)) {
                throw new AgentException(AgentException::INVALID_INPUT, 'jwk coordinates are base64url.');
            }
        }
        if (isset($jwk['alg']) && $jwk['alg'] !== $alg) {
            throw new AgentException(AgentException::INVALID_INPUT, 'jwk.alg does not match the key type.');
        }
        $kid = $jwk['kid'] ?? null;
        if ($kid !== null && (!is_string($kid) || preg_match('/^[A-Za-z0-9_.:-]{1,128}$/', $kid) !== 1)) {
            throw new AgentException(AgentException::INVALID_INPUT, 'jwk.kid is at most 128 characters.');
        }
        try {
            $thumbprint = Jwt::thumbprint($jwk);
        } catch (OAuthException $exception) {
            throw new AgentException(AgentException::INVALID_INPUT, 'jwk: ' . $exception->description);
        }
        $public = ['kty' => $jwk['kty'], 'crv' => $jwk['crv'], 'x' => $jwk['x']];
        if (isset($jwk['y'])) {
            $public['y'] = $jwk['y'];
        }

        return [...$public, 'alg' => $alg, 'kid' => $kid ?? $thumbprint, 'use' => 'sig'];
    }

    /**
     * The JOSE algorithm a key signs with, by its type and curve; null for a key this plugin does not take.
     *
     * @param array<string, mixed> $jwk
     */
    public static function algorithmOf(array $jwk): ?string
    {
        return match ([$jwk['kty'] ?? null, $jwk['crv'] ?? null]) {
            ['EC', 'P-256'] => isset($jwk['x'], $jwk['y']) ? self::ES256 : null,
            ['OKP', 'Ed25519'] => isset($jwk['x']) ? self::EDDSA : null,
            default => null,
        };
    }
}

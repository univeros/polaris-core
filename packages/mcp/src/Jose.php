<?php

declare(strict_types=1);

namespace Polaris\Mcp;

use function base64_decode;
use function base64_encode;
use function explode;
use function hash;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function rtrim;
use function strtr;
use function substr_count;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * The JOSE helpers the protected resource needs on its own (it does not require polaris/oauth-provider):
 * base64url, a JWT's unverified header, the RFC 7638 thumbprint of a public JWK.
 */
final class Jose
{
    /** The asymmetric algorithms accepted for an access token and for a DPoP proof. */
    public const array ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];

    private function __construct()
    {
    }

    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $encoded): string
    {
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }

    /**
     * The decoded header of a compact JWS, without verifying it; null for anything else.
     *
     * @return array<string, mixed>|null
     */
    public static function header(string $jwt): ?array
    {
        if (substr_count($jwt, '.') !== 2) {
            return null;
        }
        $decoded = json_decode(self::base64UrlDecode(explode('.', $jwt)[0]), true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * The RFC 7638 thumbprint (SHA-256, base64url) of a public JWK; null for a key type it cannot name.
     *
     * @param array<string, mixed> $jwk
     */
    public static function thumbprint(array $jwk): ?string
    {
        $members = match ($jwk['kty'] ?? null) {
            'RSA' => ['e', 'kty', 'n'],
            'EC' => ['crv', 'kty', 'x', 'y'],
            'OKP' => ['crv', 'kty', 'x'],
            default => null,
        };
        if ($members === null) {
            return null;
        }
        $canonical = [];
        foreach ($members as $member) {
            if (!is_string($jwk[$member] ?? null)) {
                return null;
            }
            $canonical[$member] = $jwk[$member];
        }

        return self::base64UrlEncode(hash('sha256', json_encode($canonical, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), true));
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Agent;

use InvalidArgumentException;

use function hash;
use function random_bytes;
use function strcspn;
use function strtoupper;
use function substr;
use function time;

/**
 * The signed request JWT of the agent protocol (`typ: agent+jwt`): `sub` = the agent, `aud` = the exact
 * URL called (no query), `iat`, `exp`, a random `jti`, and the request binding Polaris checks when
 * present: `htm`, `htu` and, for a body, `body_hash` (base64url SHA-256 of the exact bytes sent); and
 * the `private_key_jwt` client assertion (RFC 7523) for the token endpoint.
 */
final class RequestJwt
{
    public const string TYP = 'agent+jwt';
    public const int DEFAULT_TTL = 60;
    public const int MAX_TTL = 300;
    public const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    private function __construct()
    {
    }

    /**
     * @param list<string>|null $capabilities the grants this JWT may use; null for every live grant
     * @param (callable(): int)|null $now
     */
    public static function sign(AgentKey $key, string $agentId, string $method, string $url, ?string $body, ?array $capabilities = null, int $ttl = self::DEFAULT_TTL, ?callable $now = null): string
    {
        if ($ttl < 1 || $ttl > self::MAX_TTL) {
            throw new InvalidArgumentException('ttl is between 1 and ' . self::MAX_TTL . ' seconds.');
        }
        $issued = $now === null ? time() : $now();
        $aud = self::canonical($url);
        $claims = ['sub' => $agentId, 'aud' => $aud, 'iat' => $issued, 'exp' => $issued + $ttl, 'jti' => self::jti(), 'htm' => strtoupper($method), 'htu' => $aud];
        if ($body !== null) {
            $claims['body_hash'] = AgentKey::base64Url(hash('sha256', $body, true));
        }
        if ($capabilities !== null) {
            $claims['capabilities'] = $capabilities;
        }

        return $key->sign($claims, ['typ' => self::TYP]);
    }

    /**
     * @param (callable(): int)|null $now
     */
    public static function assertion(AgentKey $key, string $agentId, string $tokenEndpoint, ?callable $now = null): string
    {
        $issued = $now === null ? time() : $now();

        return $key->sign(['iss' => $agentId, 'sub' => $agentId, 'aud' => $tokenEndpoint, 'jti' => self::jti(), 'iat' => $issued, 'exp' => $issued + self::MAX_TTL], ['typ' => 'JWT']);
    }

    /** The exact URL an `aud` names: scheme, host, port and path, never the query or fragment. */
    public static function canonical(string $url): string
    {
        $cut = strcspn($url, '?#');

        return substr($url, 0, $cut);
    }

    public static function jti(): string
    {
        return AgentKey::base64Url(random_bytes(16));
    }
}

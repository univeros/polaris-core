<?php

declare(strict_types=1);

namespace Polaris\Mcp\Protect;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Polaris\Mcp\Jose;
use Polaris\Mcp\McpException;
use Psr\Clock\ClockInterface;
use Throwable;

use function array_intersect;
use function in_array;
use function is_array;
use function is_float;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use function preg_match;

use const JSON_THROW_ON_ERROR;

/**
 * Verifies an access token locally, as a resource server does (RFC 9068 §4): the signature by `kid`
 * against the issuer's keys (local PEMs, or a {@see Jwks}), `iss`, an `aud` naming this resource,
 * `exp` and `nbf` with a minute's leeway. Answers the claims; the DPoP binding (`cnf.jkt`) is the
 * middleware's to check against the proof.
 */
final class TokenVerifier
{
    private const int LEEWAY = 60;

    /**
     * @param list<string> $audiences the `aud` values naming this resource
     * @param array<string, string> $keys kid => PEM public key (a local issuer)
     */
    private function __construct(
        private readonly string $issuer,
        private readonly array $audiences,
        private readonly ClockInterface $clock,
        private readonly array $keys,
        private readonly ?Jwks $jwks,
    ) {
    }

    /**
     * @param list<string> $audiences
     * @param array<string, string> $keys kid => PEM public key
     */
    public static function withKeys(string $issuer, array $audiences, array $keys, ClockInterface $clock): self
    {
        return new self($issuer, $audiences, $clock, $keys, null);
    }

    /**
     * @param list<string> $audiences
     */
    public static function withJwks(string $issuer, array $audiences, Jwks $jwks, ClockInterface $clock): self
    {
        return new self($issuer, $audiences, $clock, [], $jwks);
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    /**
     * @return array<string, mixed> the verified claims
     * @throws McpException `unauthorized`
     */
    public function verify(string $jwt): array
    {
        if (preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $jwt) !== 1) {
            throw $this->invalid('The token is not a JWT.');
        }
        $header = Jose::header($jwt);
        $kid = $header['kid'] ?? null;
        $alg = $header['alg'] ?? null;
        if (!is_string($kid) || $kid === '' || !is_string($alg) || !in_array($alg, Jose::ALGORITHMS, true)) {
            throw $this->invalid('The token needs a kid and an asymmetric alg.');
        }
        try {
            JWT::$leeway = self::LEEWAY;
            JWT::$timestamp = $this->clock->now()->getTimestamp();
            $decoded = JWT::decode($jwt, $this->key($kid, $alg));
            /** @var array<string, mixed> $claims */
            $claims = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR);
        } catch (McpException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw $this->invalid('The token does not verify.');
        }
        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw $this->invalid('The token is from another issuer.');
        }
        if (!is_int($claims['exp'] ?? null) && !is_float($claims['exp'] ?? null)) {
            throw $this->invalid('The token has no expiry.');
        }
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];
        if (array_intersect($this->audiences, $audiences) === []) {
            throw $this->invalid('The token is meant for another resource.');
        }

        return $claims;
    }

    /**
     * @throws McpException
     */
    private function key(string $kid, string $alg): Key
    {
        if ($this->jwks === null) {
            $pem = $this->keys[$kid] ?? null;
            if ($pem === null) {
                throw $this->invalid('The token names an unknown signing key.');
            }

            return new Key($pem, $alg);
        }
        foreach ([false, true] as $fresh) {
            try {
                $keys = JWK::parseKeySet($this->jwks->keys($fresh), $alg);
            } catch (McpException $exception) {
                throw $exception;
            } catch (Throwable) {
                throw $this->invalid('The issuer\'s keys could not be read.');
            }
            if (($keys[$kid] ?? null) instanceof Key) {
                return $keys[$kid];
            }
        }

        throw $this->invalid('The token names an unknown signing key.');
    }

    private function invalid(string $detail): McpException
    {
        return new McpException(McpException::UNAUTHORIZED, $detail, 401);
    }
}

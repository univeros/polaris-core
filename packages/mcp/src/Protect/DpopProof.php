<?php

declare(strict_types=1);

namespace Polaris\Mcp\Protect;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Polaris\Mcp\Jose;
use Polaris\Mcp\McpException;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;
use Throwable;

use function abs;
use function explode;
use function hash;
use function hash_equals;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function preg_match;
use function strtoupper;

/**
 * The resource server's side of DPoP (RFC 9449 §4.3): the `DPoP` header is a JWT signed with the key
 * in its own header, `typ: dpop+jwt`, bound to the method and URL called (`htm`, `htu`, without query)
 * and to the access token presented (`ath`), at most five minutes old, its `jti` used once. Answers the
 * key's thumbprint, which must equal the token's `cnf.jkt`. Its own small check, so polaris/mcp does not
 * need polaris/oauth-provider; the replay cache is keyed apart from the provider's.
 */
final class DpopProof
{
    public const string HEADER = 'DPoP';
    private const string TYP = 'dpop+jwt';
    private const int MAX_AGE = 300;
    private const string REPLAY_PREFIX = 'polaris.mcp.dpop.';

    public function __construct(private readonly CacheInterface $cache, private readonly ClockInterface $clock)
    {
    }

    /**
     * @throws McpException `unauthorized`
     */
    public function thumbprint(string $proof, string $method, string $url, string $accessToken): string
    {
        if (preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $proof) !== 1) {
            throw $this->invalid('The DPoP proof is not a JWT.');
        }
        $header = Jose::header($proof);
        $alg = $header['alg'] ?? null;
        if (!is_array($header) || ($header['typ'] ?? null) !== self::TYP || !is_string($alg) || !in_array($alg, Jose::ALGORITHMS, true)) {
            throw $this->invalid('The DPoP proof needs typ dpop+jwt and an asymmetric alg.');
        }
        $jwk = $header['jwk'] ?? null;
        if (!is_array($jwk) || isset($jwk['d']) || isset($jwk['p']) || isset($jwk['q'])) {
            throw $this->invalid('The DPoP proof must carry its public key in jwk, and only the public part.');
        }
        $thumbprint = Jose::thumbprint($jwk);
        if ($thumbprint === null) {
            throw $this->invalid('The DPoP key type is not supported.');
        }
        try {
            $key = JWK::parseKey($jwk, $alg);
            JWT::$leeway = 0;
            JWT::$timestamp = $this->clock->now()->getTimestamp();
            $claims = $key === null ? null : (array) JWT::decode($proof, $key);
        } catch (Throwable) {
            $claims = null;
        }
        if ($claims === null) {
            throw $this->invalid('The DPoP proof does not verify.');
        }
        $jti = $claims['jti'] ?? null;
        $iat = $claims['iat'] ?? null;
        if (!is_string($jti) || $jti === '' || !is_int($iat) || abs($this->clock->now()->getTimestamp() - $iat) > self::MAX_AGE) {
            throw $this->invalid('The DPoP proof needs jti and a recent iat.');
        }
        $htu = $claims['htu'] ?? null;
        if (($claims['htm'] ?? null) !== strtoupper($method) || !is_string($htu) || explode('?', $htu, 2)[0] !== explode('?', $url, 2)[0]) {
            throw $this->invalid('The DPoP proof is bound to another method or URL.');
        }
        $ath = $claims['ath'] ?? null;
        if (!is_string($ath) || !hash_equals(Jose::base64UrlEncode(hash('sha256', $accessToken, true)), $ath)) {
            throw $this->invalid('The DPoP proof is not bound to the access token presented.');
        }
        $replayKey = self::REPLAY_PREFIX . hash('sha256', $thumbprint . '|' . $jti);
        if ($this->cache->get($replayKey) !== null) {
            throw $this->invalid('The DPoP proof was already used.');
        }
        $this->cache->set($replayKey, 1, self::MAX_AGE * 2);

        return $thumbprint;
    }

    private function invalid(string $detail): McpException
    {
        return new McpException(McpException::UNAUTHORIZED, $detail, 401);
    }
}

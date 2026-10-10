<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT as FirebaseJwt;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;
use Throwable;

use function abs;
use function explode;
use function hash;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function parse_url;
use function preg_match;
use function sprintf;
use function strtoupper;

use const PHP_URL_FRAGMENT;
use const PHP_URL_QUERY;

/**
 * DPoP (RFC 9449): verifies the proof a client sends in the `DPoP` header (a JWT signed with the key
 * in its own header, bound to the method and URL called, fresh, used once, and to the access token
 * when one is presented) and answers the key's thumbprint, the `cnf.jkt` a token is bound to.
 */
final class Dpop
{
    public const string HEADER = 'DPoP';
    private const string TYP = 'dpop+jwt';
    private const array ALGORITHMS = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'EdDSA'];
    private const int MAX_AGE = 300;
    private const string REPLAY_PREFIX = 'polaris.oauth.dpop.';

    public function __construct(private readonly CacheInterface $cache, private readonly ClockInterface $clock)
    {
    }

    /**
     * The thumbprint of the key that signed a valid proof for `$method` on `$url` (and for
     * `$accessToken` when given), or null when no proof was sent.
     *
     * @throws OAuthException `invalid_dpop_proof`
     */
    public function verify(?string $proof, string $method, string $url, ?string $accessToken = null): ?string
    {
        if ($proof === null || $proof === '') {
            return null;
        }
        if (preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $proof) !== 1) {
            throw $this->invalid('The proof is not a JWT.');
        }
        $header = json_decode(Jwt::base64UrlDecode(explode('.', $proof)[0]), true);
        if (!is_array($header) || ($header['typ'] ?? null) !== self::TYP || !Jwt::supportsAlgorithm($header['alg'] ?? null, self::ALGORITHMS)) {
            throw $this->invalid('The proof needs typ dpop+jwt and an asymmetric alg.');
        }
        $jwk = $header['jwk'] ?? null;
        if (!is_array($jwk) || isset($jwk['d']) || isset($jwk['p']) || isset($jwk['q'])) {
            throw $this->invalid('The proof must carry its public key in jwk, and only the public part.');
        }
        try {
            $key = JWK::parseKey($jwk, (string) $header['alg']);
            if ($key === null) {
                throw $this->invalid('The key could not be read.');
            }
            FirebaseJwt::$leeway = 0;
            FirebaseJwt::$timestamp = $this->clock->now()->getTimestamp();
            $claims = (array) FirebaseJwt::decode($proof, $key);
        } catch (OAuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw $this->invalid('The proof does not verify: ' . $exception->getMessage());
        }
        $jti = $claims['jti'] ?? null;
        $iat = $claims['iat'] ?? null;
        if (!is_string($jti) || $jti === '' || !is_int($iat)) {
            throw $this->invalid('The proof needs jti and iat.');
        }
        if (abs($this->clock->now()->getTimestamp() - $iat) > self::MAX_AGE) {
            throw $this->invalid(sprintf('The proof is older than %d seconds, or from the future.', self::MAX_AGE));
        }
        if (($claims['htm'] ?? null) !== strtoupper($method) || !is_string($claims['htu'] ?? null) || self::canonical($claims['htu']) !== self::canonical($url)) {
            throw $this->invalid('The proof is bound to another method or URL.');
        }
        if ($accessToken !== null && ($claims['ath'] ?? null) !== Jwt::base64UrlEncode(hash('sha256', $accessToken, true))) {
            throw $this->invalid('The proof is not bound to the access token presented.');
        }
        $thumbprint = Jwt::thumbprint($jwk);
        $replayKey = self::REPLAY_PREFIX . hash('sha256', $thumbprint . '|' . $jti);
        if ($this->cache->get($replayKey) !== null) {
            throw $this->invalid('The proof was already used.');
        }
        $this->cache->set($replayKey, 1, self::MAX_AGE * 2);

        return $thumbprint;
    }

    /**
     * The `htu` form of a URL: scheme, host, port and path, without query or fragment (RFC 9449 §4.3).
     */
    public static function canonical(string $url): string
    {
        $query = parse_url($url, PHP_URL_QUERY);
        $fragment = parse_url($url, PHP_URL_FRAGMENT);
        $trimmed = $url;
        if (is_string($query)) {
            $trimmed = explode('?', $trimmed, 2)[0];
        }
        if (is_string($fragment)) {
            $trimmed = explode('#', $trimmed, 2)[0];
        }

        return $trimmed;
    }

    private function invalid(string $description): OAuthException
    {
        return new OAuthException(OAuthException::INVALID_DPOP_PROOF, $description, 400);
    }
}

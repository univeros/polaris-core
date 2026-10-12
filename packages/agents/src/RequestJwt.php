<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT as FirebaseJwt;
use Polaris\Agents\Model\Agent;
use Polaris\OAuth\Dpop;
use Polaris\OAuth\Jwt;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;
use Throwable;

use function array_filter;
use function array_values;
use function count;
use function explode;
use function hash;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function max;
use function min;
use function preg_match;
use function sprintf;
use function strlen;
use function strtoupper;

/**
 * The signed request JWT of the agent protocol (`docs/better/agent-auth-compat.md`): `typ: agent+jwt`,
 * `alg` ES256 or EdDSA, verified with the agent's registered key only (no `jku`, `x5u` or `jwk`
 * header), `sub` = the agent, `aud` = the exact URL called, `iat`/`exp` at most `requestJwtMaxAge`
 * apart with 60 seconds of leeway, `jti` once per agent until `exp`, optional `htm`, `htu` and
 * `body_hash` request binding checked when present, optional `capabilities`.
 */
final class RequestJwt
{
    public const string TYP = 'agent+jwt';
    public const int LEEWAY = 60;
    private const int MAX_LENGTH = 8192;
    private const int MAX_CAPABILITIES = 50;
    private const string REPLAY_PREFIX = 'polaris.agents.jti.';

    public function __construct(
        private readonly Settings $settings,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * The unverified `sub` of a JWT that claims to be an agent JWT, to find the agent whose key verifies
     * it; null when the token is not an agent JWT at all.
     *
     * @return array{sub: string, header: array<string, mixed>}|null
     */
    public static function peek(string $jwt): ?array
    {
        if (strlen($jwt) > self::MAX_LENGTH || preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $jwt) !== 1) {
            return null;
        }
        $header = Jwt::header($jwt);
        if ($header === null || ($header['typ'] ?? null) !== self::TYP) {
            return null;
        }
        $payload = json_decode(Jwt::base64UrlDecode(explode('.', $jwt)[1]), true);
        $sub = is_array($payload) && is_string($payload['sub'] ?? null) ? $payload['sub'] : '';

        return ['sub' => $sub, 'header' => $header];
    }

    /**
     * The verified claims of the JWT for this request.
     *
     * @param string $method the request method
     * @param string $url the request URL, as called
     * @param string $body the raw request body
     * @return array{capabilities: list<string>|null, claims: array<string, mixed>}
     * @throws AgentException `invalid_jwt`, `aud_mismatch`
     */
    public function verify(string $jwt, Agent $agent, string $method, string $url, string $body): array
    {
        $peeked = self::peek($jwt);
        if ($peeked === null) {
            throw $this->invalid('The credential is not an agent JWT (typ agent+jwt).');
        }
        $header = $peeked['header'];
        if (isset($header['jku']) || isset($header['x5u']) || isset($header['jwk']) || isset($header['x5c'])) {
            throw $this->invalid('The JWT must not carry a key or a key URL; the agent\'s registered key verifies it.');
        }
        $alg = $header['alg'] ?? null;
        $jwk = $agent->publicJwk;
        if ($jwk === null) {
            throw $this->invalid('The agent has no registered key; it authenticates with an access token.');
        }
        if (!is_string($alg) || !in_array($alg, AgentKeys::ALGORITHMS, true) || $alg !== AgentKeys::algorithmOf($jwk)) {
            throw $this->invalid('alg must be ES256 or EdDSA and match the agent\'s key.');
        }
        try {
            $key = JWK::parseKey($jwk, $alg);
            if ($key === null) {
                throw $this->invalid('The agent\'s key could not be read.');
            }
            FirebaseJwt::$leeway = self::LEEWAY;
            FirebaseJwt::$timestamp = $this->clock->now()->getTimestamp();
            $claims = (array) FirebaseJwt::decode($jwt, $key);
        } catch (AgentException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw $this->invalid('The JWT does not verify: ' . $exception->getMessage());
        }
        $this->assertClaims($claims, $agent, $method, $url, $body);
        $this->assertFresh($agent, $claims);

        return ['capabilities' => self::capabilities($claims), 'claims' => $claims];
    }

    /**
     * @param array<string, mixed> $claims
     * @throws AgentException
     */
    private function assertClaims(array $claims, Agent $agent, string $method, string $url, string $body): void
    {
        if (($claims['sub'] ?? null) !== $agent->id) {
            throw $this->invalid('sub must be the agent\'s id.');
        }
        $iat = $claims['iat'] ?? null;
        $exp = $claims['exp'] ?? null;
        if (!is_int($iat) || !is_int($exp) || $exp <= $iat) {
            throw $this->invalid('iat and exp are required, exp after iat.');
        }
        if ($exp - $iat > $this->settings->requestJwtMaxAge) {
            throw $this->invalid(sprintf('exp - iat must be at most %d seconds.', $this->settings->requestJwtMaxAge));
        }
        $aud = $claims['aud'] ?? null;
        // The URL called, compared normalised ({@see Url}) so a proxy's trailing slash or port spelling is no mismatch.
        if (!is_string($aud) || Dpop::canonical($aud) !== $aud || Url::normalize($aud) !== Url::normalize($url)) {
            throw new AgentException(AgentException::AUD_MISMATCH, 'aud must be the exact URL called (scheme, host, port, path; no query).');
        }
        if (isset($claims['htm']) && (!is_string($claims['htm']) || strtoupper($claims['htm']) !== strtoupper($method))) {
            throw $this->invalid('htm does not match the request method.');
        }
        if (isset($claims['htu']) && (!is_string($claims['htu']) || Url::normalize($claims['htu']) !== Url::normalize($url))) {
            throw $this->invalid('htu does not match the request URL.');
        }
        if (isset($claims['body_hash']) && (!is_string($claims['body_hash']) || $claims['body_hash'] !== Jwt::base64UrlEncode(hash('sha256', $body, true)))) {
            throw $this->invalid('body_hash does not match the request body.');
        }
        $capabilities = $claims['capabilities'] ?? null;
        if ($capabilities !== null && (!is_array($capabilities) || count($capabilities) > self::MAX_CAPABILITIES || count(array_filter($capabilities, is_string(...))) !== count($capabilities))) {
            throw $this->invalid('capabilities is a list of capability names.');
        }
    }

    /**
     * `jti` once per agent until the JWT expires: the cache entry is written only when absent (the
     * closest a PSR-16 cache comes to set-if-absent), as the provider's DPoP replay check does.
     *
     * @param array<string, mixed> $claims
     * @throws AgentException
     */
    private function assertFresh(Agent $agent, array $claims): void
    {
        $jti = $claims['jti'] ?? null;
        if (!is_string($jti) || $jti === '' || strlen($jti) > 256) {
            throw $this->invalid('jti is required.');
        }
        $key = self::REPLAY_PREFIX . hash('sha256', $agent->id . '|' . $jti);
        if ($this->cache->get($key) !== null) {
            throw $this->invalid('The JWT was already used (jti).');
        }
        $ttl = (int) $claims['exp'] - $this->clock->now()->getTimestamp() + self::LEEWAY;
        $this->cache->set($key, 1, min($this->settings->requestJwtMaxAge + 2 * self::LEEWAY, max(self::LEEWAY, $ttl)));
    }

    /**
     * @param array<string, mixed> $claims
     * @return list<string>|null
     */
    private static function capabilities(array $claims): ?array
    {
        $capabilities = $claims['capabilities'] ?? null;

        return is_array($capabilities) ? array_values(array_filter($capabilities, is_string(...))) : null;
    }

    private function invalid(string $detail): AgentException
    {
        return new AgentException(AgentException::INVALID_JWT, $detail);
    }
}

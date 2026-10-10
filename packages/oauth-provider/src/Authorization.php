<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Polaris\OAuth\Model\Client;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

use function array_filter;
use function http_build_query;
use function in_array;
use function is_array;
use function is_string;
use function preg_match;
use function random_bytes;
use function str_contains;

/**
 * The authorization endpoint's half: a request is validated against the client (redirect URI exact,
 * `code` with an S256 challenge, known scopes) and parked in the cache under an unguessable id until
 * the user decides; a decision records the consent, mints the code and builds the redirect. A trusted
 * client, or scopes the user already granted, need no screen.
 */
final class Authorization
{
    public const string RESPONSE_TYPE = 'code';
    private const string CACHE_PREFIX = 'polaris.oauth.request.';
    private const int TTL = 600;

    public function __construct(
        private readonly Clients $clients,
        private readonly Scopes $scopes,
        private readonly Codes $codes,
        private readonly Consents $consents,
        private readonly Settings $settings,
        private readonly Jwt $jwt,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * Validates the query of `GET /oauth2/authorize` and parks it.
     *
     * @param array<string, mixed> $query
     * @return array{PendingRequest, Client}
     * @throws OAuthException the errors that cannot be sent to the redirect URI (`invalid_request`,
     *                        `invalid_client` for an unknown client or redirect) or can (`invalid_scope`, ...)
     */
    public function start(array $query): array
    {
        $clientId = self::text($query['client_id'] ?? null);
        $client = $clientId === null ? null : $this->clients->find($clientId);
        if ($client === null || $client->disabledAt !== null) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'Unknown client.', 400);
        }
        $redirectUri = self::text($query['redirect_uri'] ?? null);
        if ($redirectUri === null || !$client->allowsRedirect($redirectUri)) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'redirect_uri is required and must be one the client registered.', 400);
        }
        if (!$client->allowsGrant(Clients::GRANT_CODE)) {
            throw new OAuthException(OAuthException::UNAUTHORIZED_CLIENT, 'The client may not use the authorization code grant.');
        }
        if (self::text($query['response_type'] ?? null) !== self::RESPONSE_TYPE) {
            throw new OAuthException(OAuthException::UNSUPPORTED_RESPONSE_TYPE, 'response_type must be code.');
        }
        $challenge = self::text($query['code_challenge'] ?? null);
        if ($challenge === null || preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge) !== 1 || self::text($query['code_challenge_method'] ?? null) !== 'S256') {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'PKCE is required: code_challenge (S256, base64url) and code_challenge_method=S256.');
        }
        $scopes = $this->scopes->parse(self::text($query['scope'] ?? null), $client);
        $resource = self::text($query['resource'] ?? null);
        if ($resource !== null && (preg_match('~^https?://[^\s#]+$~', $resource) !== 1)) {
            throw new OAuthException(OAuthException::INVALID_TARGET, 'resource must be an absolute URI without a fragment.');
        }
        $dpopJkt = self::text($query['dpop_jkt'] ?? null);
        if ($dpopJkt !== null && preg_match('/^[A-Za-z0-9_-]{43}$/', $dpopJkt) !== 1) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'dpop_jkt is a base64url SHA-256 thumbprint.');
        }
        $prompt = self::text($query['prompt'] ?? null);
        if ($prompt !== null && !in_array($prompt, ['none', 'login', 'consent'], true)) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'prompt is none, login or consent.');
        }
        $request = new PendingRequest(
            Jwt::base64UrlEncode(random_bytes(24)),
            $client->clientId,
            $redirectUri,
            $scopes,
            self::text($query['state'] ?? null),
            $challenge,
            self::text($query['nonce'] ?? null),
            $resource,
            $dpopJkt,
            $prompt,
            $this->clock->now()->getTimestamp(),
        );
        $this->cache->set(self::CACHE_PREFIX . $request->id, $request->toArray(), self::TTL);

        return [$request, $client];
    }

    /**
     * @return array{PendingRequest, Client}
     * @throws OAuthException `invalid_request` when the id is unknown or expired
     */
    public function pending(?string $id): array
    {
        $data = $id === null || $id === '' || str_contains($id, '/') ? null : $this->cache->get(self::CACHE_PREFIX . $id);
        if (!is_array($data)) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'The authorization request is unknown or expired; start again.');
        }
        $request = PendingRequest::fromArray($data);
        $client = $this->clients->find($request->clientId);
        if ($client === null) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'Unknown client.', 400);
        }

        return [$request, $client];
    }

    /**
     * Whether the user must be shown the scopes: no for a trusted client or scopes already granted,
     * yes when the client asked for `prompt=consent`.
     */
    public function needsConsent(PendingRequest $request, Client $client, string $userId): bool
    {
        if ($request->prompt === 'consent') {
            return true;
        }
        if ($client->trusted || in_array($client->clientId, $this->settings->trustedClients, true)) {
            return false;
        }

        return !$this->consents->covers($userId, $client->clientId, $request->scopes);
    }

    /**
     * The user's decision: the code and the redirect that carries it, or the refusal's redirect.
     *
     * @return array{string, bool} the redirect URL, and whether a consent was recorded
     * @throws OAuthException `invalid_request`
     */
    public function decide(PendingRequest $request, Client $client, string $userId, ?string $organizationId, bool $approve, ?int $authTime): array
    {
        $this->cache->delete(self::CACHE_PREFIX . $request->id);
        if (!$approve) {
            return [self::redirect($request->redirectUri, ['error' => OAuthException::ACCESS_DENIED, 'error_description' => 'The user refused.', 'state' => $request->state]), false];
        }
        $recorded = false;
        if (!$client->trusted && !in_array($client->clientId, $this->settings->trustedClients, true)) {
            $this->consents->grant($userId, $client->clientId, $organizationId, $request->scopes);
            $recorded = true;
        }
        $code = $this->codes->issue($client, $userId, $organizationId, $request->scopes, $request->redirectUri, $request->codeChallenge, $request->nonce, $request->resource, $request->dpopJkt, $authTime);

        // RFC 9207: the response names its issuer, so a client talking to several servers cannot be mixed up.
        return [self::redirect($request->redirectUri, ['code' => $code, 'state' => $request->state, 'iss' => $this->jwt->issuer()]), $recorded];
    }

    /**
     * The redirect URI with the parameters appended (RFC 6749 §4.1.2 / §4.1.2.1), `null`s left out.
     *
     * @param array<string, string|null> $params
     */
    public static function redirect(string $uri, array $params): string
    {
        $query = http_build_query(array_filter($params, static fn(?string $value): bool => $value !== null));

        return $uri . (str_contains($uri, '?') ? '&' : '?') . $query;
    }

    private static function text(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}

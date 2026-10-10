<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Ciba;
use Polaris\OAuth\Clients;
use Polaris\OAuth\CodeReused;
use Polaris\OAuth\Codes;
use Polaris\OAuth\Devices;
use Polaris\OAuth\Discovery;
use Polaris\OAuth\Dpop;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\Exchange;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\Scopes;
use Polaris\OAuth\Settings;
use Polaris\OAuth\Tokens;
use Psr\EventDispatcher\EventDispatcherInterface;

use function in_array;
use function preg_match;
use function str_contains;

/**
 * `POST /oauth2/token`: every grant. The client authenticates the way it registered; a DPoP proof
 * binds the tokens to its key; the response is never cached.
 */
final class TokenEndpoint extends OAuthEndpoint
{
    public function __construct(
        private readonly Clients $clients,
        private readonly Codes $codes,
        private readonly Tokens $tokens,
        private readonly Scopes $scopes,
        private readonly Devices $devices,
        private readonly Ciba $ciba,
        private readonly Exchange $exchange,
        private readonly Dpop $dpop,
        private readonly Discovery $discovery,
        private readonly Settings $settings,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $grant = self::text($input, 'grant_type');
        $client = null;
        try {
            $client = $this->authenticatedClient($this->clients, $this->discovery, $input, '/oauth2/token');
            $jkt = $this->proof($this->dpop, $this->settings, $input, $client);
            $response = match ($grant) {
                Clients::GRANT_CODE => $this->code($input, $client, $jkt),
                Clients::GRANT_REFRESH => $this->refresh($input, $client, $jkt),
                Clients::GRANT_CLIENT => $this->clientCredentials($input, $client, $jkt),
                Clients::GRANT_DEVICE => $this->device($input, $client, $jkt),
                Clients::GRANT_CIBA => $this->backchannel($input, $client, $jkt),
                Clients::GRANT_EXCHANGE => $this->exchange($input, $client, $jkt),
                null => throw new OAuthException(OAuthException::INVALID_REQUEST, 'grant_type is required.'),
                default => throw new OAuthException(OAuthException::UNSUPPORTED_GRANT_TYPE, 'Unsupported grant_type.'),
            };
        } catch (OAuthException $exception) {
            if ($client !== null && !in_array($exception->error, [OAuthException::AUTHORIZATION_PENDING, OAuthException::SLOW_DOWN], true)) {
                $this->events->dispatch(new OAuthEvent(AuditNames::TOKEN_REFUSED, null, $client->clientId, null, ['grant' => $grant, 'error' => $exception->error], $this->client($input)->ip, $this->client($input)->userAgent));
            }

            return $this->refuse($exception);
        }
        $this->events->dispatch(new OAuthEvent(AuditNames::TOKEN_ISSUED, $response['_user'] ?? null, $client->clientId, $response['_org'] ?? null, ['grant' => $grant, 'scope' => $response['scope'] ?? '', 'dpop' => $jkt !== null, 'act' => $response['_act'] ?? null], $this->client($input)->ip, $this->client($input)->userAgent));
        unset($response['_user'], $response['_org'], $response['_act']);

        return $this->tokenResponse($response);
    }

    /**
     * @return array<string, mixed>
     */
    private function code(Input $input, Client $client, ?string $jkt): array
    {
        $code = self::text($input, 'code');
        if ($code === null) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'code is required.');
        }
        try {
            $stored = $this->codes->consume($code, $client, self::text($input, 'redirect_uri'), self::text($input, 'code_verifier'));
        } catch (CodeReused $reused) {
            $this->tokens->revokeFamily($reused->codeId);
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The authorization code was already used; the tokens it issued are revoked.');
        }
        if ($stored->dpopJkt !== null && $stored->dpopJkt !== $jkt) {
            throw new OAuthException(OAuthException::INVALID_DPOP_PROOF, 'The code was bound to another DPoP key (dpop_jkt).');
        }
        // The tokens' family is the code, so a replay of the code can end them.
        $response = $this->tokens->issue($client, $stored->userId, $stored->organizationId, $stored->scopes, $stored->resource, $jkt, null, $stored->authTime, $stored->nonce, $stored->id);

        return [...$response, '_user' => $stored->userId, '_org' => $stored->organizationId];
    }

    /**
     * @return array<string, mixed>
     */
    private function refresh(Input $input, Client $client, ?string $jkt): array
    {
        $token = self::text($input, 'refresh_token');
        if ($token === null) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'refresh_token is required.');
        }
        try {
            $response = $this->tokens->refresh($token, $client, $jkt, self::words($input, 'scope'));
        } catch (OAuthException $exception) {
            if (str_contains($exception->description, 'family')) {
                $this->events->dispatch(new OAuthEvent(AuditNames::REFRESH_REUSED, null, $client->clientId, null, [], $this->client($input)->ip, $this->client($input)->userAgent));
            }
            throw $exception;
        }

        return $response;
    }

    /**
     * @return array<string, mixed>
     */
    private function clientCredentials(Input $input, Client $client, ?string $jkt): array
    {
        if ($client->type === Client::TYPE_PUBLIC || !$client->allowsGrant(Clients::GRANT_CLIENT)) {
            throw new OAuthException(OAuthException::UNAUTHORIZED_CLIENT, 'The client may not use client_credentials.');
        }
        $scopes = $this->scopes->parse(self::text($input, 'scope'), $client);
        if (in_array(Scopes::OPENID, $scopes, true) || in_array(Scopes::OFFLINE_ACCESS, $scopes, true)) {
            throw new OAuthException(OAuthException::INVALID_SCOPE, 'openid and offline_access need a user.');
        }

        return $this->tokens->issue($client, null, $client->organizationId, $scopes, $this->resource($input), $jkt);
    }

    /**
     * @return array<string, mixed>
     */
    private function device(Input $input, Client $client, ?string $jkt): array
    {
        $deviceCode = self::text($input, 'device_code');
        if ($deviceCode === null) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'device_code is required.');
        }
        $device = $this->devices->poll($deviceCode, $client);
        $response = $this->tokens->issue($client, $device->userId, $device->organizationId, $device->scopes, $device->resource, $jkt, null, $device->authTime);

        return [...$response, '_user' => $device->userId, '_org' => $device->organizationId];
    }

    /**
     * @return array<string, mixed>
     */
    private function backchannel(Input $input, Client $client, ?string $jkt): array
    {
        $authReqId = self::text($input, 'auth_req_id');
        if ($authReqId === null) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'auth_req_id is required.');
        }
        $request = $this->ciba->poll($authReqId, $client);
        $response = $this->tokens->issue($client, $request->userId, $request->organizationId, $request->scopes, $request->resource, $jkt, null, $request->authTime);

        return [...$response, '_user' => $request->userId, '_org' => $request->organizationId];
    }

    /**
     * @return array<string, mixed>
     */
    private function exchange(Input $input, Client $client, ?string $jkt): array
    {
        $response = $this->exchange->exchange(
            $client,
            self::text($input, 'subject_token'),
            self::text($input, 'subject_token_type'),
            self::text($input, 'actor_token'),
            self::text($input, 'actor_token_type'),
            $this->resource($input) ?? self::text($input, 'audience'),
            self::words($input, 'scope'),
            $jkt,
        );

        return [...$response, '_act' => true];
    }

    private function resource(Input $input): ?string
    {
        $resource = self::text($input, 'resource');
        if ($resource !== null && preg_match('~^https?://[^\s#]+$~', $resource) !== 1) {
            throw new OAuthException(OAuthException::INVALID_TARGET, 'resource must be an absolute URI without a fragment.');
        }

        return $resource;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use Polaris\Contract\TokenParserInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\OAuth\Model\Client;
use Psr\Clock\ClockInterface;

use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function preg_match;

/**
 * Token exchange (RFC 8693): a client presents a subject token, a Polaris session's access token or
 * one of this provider's access tokens, and gets an access token for a resource, within the subject's
 * scopes, carrying `act` (the requesting client, or the actor token's subject) so every consumer
 * sees who acts for whom. The ground of program 4's agent delegation (spec §4.3).
 */
final class Exchange
{
    public const string TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';
    public const string TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';

    public function __construct(
        private readonly Jwt $jwt,
        private readonly Tokens $tokens,
        private readonly Scopes $scopes,
        private readonly TokenParserInterface $sessions,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param list<string>|null $requested the scopes asked for; null for the subject's
     * @return array<string, mixed> the RFC 8693 §2.2 response
     * @throws OAuthException `invalid_request`, `invalid_grant`, `invalid_scope`, `invalid_target`, `unauthorized_client`
     */
    public function exchange(Client $client, ?string $subjectToken, ?string $subjectTokenType, ?string $actorToken, ?string $actorTokenType, ?string $resource, ?array $requested, ?string $dpopJkt): array
    {
        if (!$client->allowsGrant(Clients::GRANT_EXCHANGE)) {
            throw new OAuthException(OAuthException::UNAUTHORIZED_CLIENT, 'The client may not exchange tokens.');
        }
        if ($subjectToken === null || !in_array($subjectTokenType, [self::TYPE_ACCESS_TOKEN, self::TYPE_JWT], true)) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'subject_token and subject_token_type (access_token or jwt) are required.');
        }
        if ($resource !== null && preg_match('~^https?://[^\s#]+$~', $resource) !== 1) {
            throw new OAuthException(OAuthException::INVALID_TARGET, 'resource must be an absolute URI.');
        }
        $subject = $this->subject($subjectToken);
        $scopes = $requested === null ? $subject['scopes'] : ($subject['scopes'] === null ? $this->scopes->parse(Scopes::join($requested), $client) : Scopes::within($requested, $subject['scopes']));
        $actor = ['client_id' => $client->clientId];
        if ($actorToken !== null) {
            if (!in_array($actorTokenType, [self::TYPE_ACCESS_TOKEN, self::TYPE_JWT], true)) {
                throw new OAuthException(OAuthException::INVALID_REQUEST, 'actor_token_type must be access_token or jwt.');
            }
            $presented = $this->subject($actorToken);
            $actor = ['sub' => $presented['sub'], 'client_id' => $presented['client_id'] ?? $client->clientId];
        }
        if ($subject['act'] !== null) {
            $actor['act'] = $subject['act'];
        }
        $response = $this->tokens->issue($client, $subject['user'], $subject['org'], $scopes ?? [], $resource, $dpopJkt, $actor, $subject['auth_time']);
        unset($response['refresh_token'], $response['id_token']);
        $response['issued_token_type'] = self::TYPE_ACCESS_TOKEN;

        return $response;
    }

    /**
     * What a subject or actor token says: a session's access token (core's parser) or one of this
     * provider's (live in the token table).
     *
     * @return array{sub: string, user: string|null, org: string|null, client_id: string|null, scopes: list<string>|null, act: array<string, mixed>|null, auth_time: int|null}
     * @throws OAuthException `invalid_grant`
     */
    private function subject(string $token): array
    {
        $header = Jwt::header($token);
        if ($header !== null && ($header['typ'] ?? null) === Tokens::TYP) {
            $claims = $this->jwt->verify($token, Tokens::TYP)['claims'];
            $record = is_string($claims['jti'] ?? null) ? $this->tokens->find($claims['jti']) : null;
            if ($record === null || !$record->isLive($this->clock->now())) {
                throw new OAuthException(OAuthException::INVALID_GRANT, 'The subject token is revoked or unknown.');
            }

            return ['sub' => (string) ($claims['sub'] ?? ''), 'user' => $record->userId, 'org' => $record->organizationId, 'client_id' => $record->clientId, 'scopes' => $record->scopes, 'act' => $record->actor, 'auth_time' => $record->authTime];
        }
        try {
            $session = $this->sessions->parse($token);
        } catch (AuthorizationTokenException) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The subject token is not a token this server knows.');
        }
        $sub = $session->getMetadata('sub');
        $org = $session->getMetadata('org');
        $authTime = $session->getMetadata('auth_time');
        if (!is_string($sub) || $sub === '') {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The subject token has no subject.');
        }

        return ['sub' => $sub, 'user' => $sub, 'org' => is_string($org) ? $org : null, 'client_id' => null, 'scopes' => null, 'act' => null, 'auth_time' => is_int($authTime) ? $authTime : null];
    }
}

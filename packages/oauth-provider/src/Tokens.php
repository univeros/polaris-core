<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\User;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\Model\Token;
use Polaris\Repository\UserRepository;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_values;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function random_bytes;
use function sprintf;
use function str_starts_with;

use const JSON_THROW_ON_ERROR;

/**
 * The tokens the provider issues: access tokens are JWTs (`typ: at+jwt`, RFC 9068) signed with core's
 * key and recorded by `jti` so they can be revoked and introspected; refresh tokens are opaque, stored
 * as keyed hashes, rotated at every use in a family whose reuse revokes the whole family; ID tokens
 * when `openid` was granted to a user.
 */
final class Tokens
{
    public const string TYP = 'at+jwt';
    private const string PEPPER_CONTEXT = 'oauth_refresh';
    private const string REFRESH_PREFIX = 'prt_';

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Pepper $pepper,
        private readonly Jwt $jwt,
        private readonly Settings $settings,
        private readonly UserRepository $users,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * The token response for a grant: the access token, `expires_in`, `scope`, a refresh token when the
     * client may refresh and a user is behind the grant, an ID token when `openid` was granted.
     *
     * @param list<string> $scopes
     * @param array<string, mixed>|null $actor the `act` claim (token exchange)
     * @return array<string, mixed>
     */
    public function issue(Client $client, ?string $userId, ?string $organizationId, array $scopes, ?string $resource, ?string $dpopJkt, ?array $actor = null, ?int $authTime = null, ?string $nonce = null, ?string $familyId = null): array
    {
        $now = $this->clock->now();
        $expiresAt = $now->modify(sprintf('+%d seconds', $this->settings->accessTokenTtl));
        $refreshable = $userId !== null && $client->allowsGrant(Clients::GRANT_REFRESH);
        $familyId ??= $refreshable ? Uuid::v7()->toRfc4122() : null;
        $access = new Token();
        $access->id = Uuid::v7()->toRfc4122();
        $access->kind = Token::KIND_ACCESS;
        $access->clientId = $client->clientId;
        $access->userId = $userId;
        $access->organizationId = $organizationId;
        $access->scopes = $scopes;
        $access->familyId = $familyId;
        $access->resource = $resource;
        $access->dpopJkt = $dpopJkt;
        $access->actor = $actor;
        $access->authTime = $authTime;
        $access->expiresAt = $expiresAt;
        $access->createdAt = $now;
        $this->database->insert(Schema::TOKENS, $this->row($access));

        $claims = [
            'sub' => $userId ?? $client->clientId,
            'jti' => $access->id,
            'aud' => $resource ?? $this->jwt->issuer(),
            'client_id' => $client->clientId,
            'scope' => Scopes::join($scopes),
        ];
        if ($organizationId !== null) {
            $claims['org'] = $organizationId;
        }
        if ($authTime !== null) {
            $claims['auth_time'] = $authTime;
        }
        if ($dpopJkt !== null) {
            $claims['cnf'] = ['jkt' => $dpopJkt];
        }
        if ($actor !== null) {
            $claims['act'] = $actor;
        }
        $response = [
            'access_token' => $this->jwt->mint($claims, $expiresAt, ['typ' => self::TYP]),
            'token_type' => $dpopJkt === null ? 'Bearer' : 'DPoP',
            'expires_in' => $this->settings->accessTokenTtl,
            'scope' => Scopes::join($scopes),
        ];
        if ($refreshable) {
            $response['refresh_token'] = $this->mintRefresh($client, (string) $userId, $organizationId, $scopes, $resource, $dpopJkt, $actor, $authTime, (string) $familyId);
        }
        $user = $userId === null ? null : $this->users->find($userId);
        if ($user instanceof User && in_array(Scopes::OPENID, $scopes, true)) {
            $response['id_token'] = $this->mintIdToken($client, $user, $scopes, $authTime, $nonce);
        }

        return $response;
    }

    /**
     * The refresh grant: the token is spent, its successor carries the same family; a spent token
     * presented again is a theft signal and ends the family.
     *
     * @param list<string>|null $requested a narrower scope, or null for the same
     * @return array<string, mixed>
     * @throws OAuthException `invalid_grant`
     */
    public function refresh(#[SensitiveParameter] string $refreshToken, Client $client, ?string $dpopJkt, ?array $requested): array
    {
        $token = $this->findRefresh($refreshToken);
        if ($token === null || $token->clientId !== $client->clientId) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The refresh token is unknown.');
        }
        $now = $this->clock->now();
        if ($token->revokedAt !== null) {
            if ($token->familyId !== null) {
                $this->revokeFamily($token->familyId);
            }
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The refresh token was already used; every token of its family is revoked.');
        }
        if ($token->expiresAt <= $now) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The refresh token expired.');
        }
        if ($token->dpopJkt !== null && $token->dpopJkt !== $dpopJkt) {
            throw new OAuthException(OAuthException::INVALID_DPOP_PROOF, 'The refresh token is bound to another DPoP key.');
        }
        if ($this->database->update(Schema::TOKENS, ['id' => $token->id, 'revoked_at' => null], ['revoked_at' => $now]) !== 1) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The refresh token was already used.');
        }
        $scopes = $requested === null ? $token->scopes : Scopes::within($requested, $token->scopes);

        return $this->issue($client, $token->userId, $token->organizationId, $scopes, $token->resource, $token->dpopJkt, $token->actor, $token->authTime, null, $token->familyId);
    }

    /**
     * RFC 7009: the client's own token stops; an unknown one is not an error.
     *
     * @return Token|null what was revoked
     */
    public function revoke(#[SensitiveParameter] string $token, Client $client): ?Token
    {
        $found = $this->lookup($token);
        if ($found === null || $found->clientId !== $client->clientId || $found->revokedAt !== null) {
            return null;
        }
        $now = $this->clock->now();
        $this->database->update(Schema::TOKENS, ['id' => $found->id], ['revoked_at' => $now]);
        $found->revokedAt = $now;
        if ($found->kind === Token::KIND_REFRESH && $found->familyId !== null) {
            $this->revokeFamily($found->familyId);
        }

        return $found;
    }

    /**
     * RFC 7662: whether the token is live, and its claims when it is.
     *
     * @return array<string, mixed>
     */
    public function introspect(#[SensitiveParameter] string $token): array
    {
        $found = $this->lookup($token);
        if ($found === null || !$found->isLive($this->clock->now())) {
            return ['active' => false];
        }
        $response = [
            'active' => true,
            'client_id' => $found->clientId,
            'token_type' => $found->dpopJkt === null ? 'Bearer' : 'DPoP',
            'scope' => Scopes::join($found->scopes),
            'sub' => $found->userId ?? $found->clientId,
            'iss' => $this->jwt->issuer(),
            'iat' => $found->createdAt->getTimestamp(),
            'exp' => $found->expiresAt->getTimestamp(),
            'jti' => $found->id,
        ];
        if ($found->resource !== null) {
            $response['aud'] = $found->resource;
        }
        if ($found->organizationId !== null) {
            $response['org'] = $found->organizationId;
        }
        if ($found->dpopJkt !== null) {
            $response['cnf'] = ['jkt' => $found->dpopJkt];
        }
        if ($found->actor !== null) {
            $response['act'] = $found->actor;
        }

        return $response;
    }

    /**
     * The record behind an access token's `jti`, live or not.
     */
    public function find(string $jti): ?Token
    {
        $row = $this->database->findOne(Schema::TOKENS, ['id' => $jti]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * A consent revoked ends every token of the user with the client.
     */
    public function revokeForUserAndClient(string $userId, string $clientId): int
    {
        return $this->database->update(Schema::TOKENS, ['user_id' => $userId, 'client_id' => $clientId, 'revoked_at' => null], ['revoked_at' => $this->clock->now()]);
    }

    public function revokeFamily(string $familyId): int
    {
        return $this->database->update(Schema::TOKENS, ['family_id' => $familyId, 'revoked_at' => null], ['revoked_at' => $this->clock->now()]);
    }

    public function deleteForUser(string $userId): void
    {
        $this->database->delete(Schema::TOKENS, ['user_id' => $userId]);
    }

    public function deleteForClient(string $clientId): void
    {
        $this->database->delete(Schema::TOKENS, ['client_id' => $clientId]);
    }

    /**
     * Rows whose token expired more than a refresh lifetime ago.
     */
    public function prune(): int
    {
        return $this->database->delete(Schema::TOKENS, ['expires_at' => Condition::lt($this->clock->now()->modify(sprintf('-%d seconds', $this->settings->refreshTokenTtl)))]);
    }

    /**
     * @param list<string> $scopes
     * @param array<string, mixed>|null $actor
     */
    private function mintRefresh(Client $client, string $userId, ?string $organizationId, array $scopes, ?string $resource, ?string $dpopJkt, ?array $actor, ?int $authTime, string $familyId): string
    {
        $now = $this->clock->now();
        $secret = self::REFRESH_PREFIX . Jwt::base64UrlEncode(random_bytes(32));
        $refresh = new Token();
        $refresh->id = Uuid::v7()->toRfc4122();
        $refresh->kind = Token::KIND_REFRESH;
        $refresh->tokenHash = $this->pepper->hash(self::PEPPER_CONTEXT, $secret);
        $refresh->clientId = $client->clientId;
        $refresh->userId = $userId;
        $refresh->organizationId = $organizationId;
        $refresh->scopes = $scopes;
        $refresh->familyId = $familyId;
        $refresh->resource = $resource;
        $refresh->dpopJkt = $dpopJkt;
        $refresh->actor = $actor;
        $refresh->authTime = $authTime;
        $refresh->expiresAt = $now->modify(sprintf('+%d seconds', $this->settings->refreshTokenTtl));
        $refresh->createdAt = $now;
        $this->database->insert(Schema::TOKENS, $this->row($refresh));

        return $secret;
    }

    /**
     * @param list<string> $scopes
     */
    private function mintIdToken(Client $client, User $user, array $scopes, ?int $authTime, ?string $nonce): string
    {
        $claims = ['sub' => $user->id, 'aud' => $client->clientId, 'jti' => Uuid::v7()->toRfc4122(), ...Scopes::claims($user, $scopes)];
        if ($authTime !== null) {
            $claims['auth_time'] = $authTime;
        }
        if ($nonce !== null) {
            $claims['nonce'] = $nonce;
        }

        return $this->jwt->mint($claims, $this->clock->now()->modify(sprintf('+%d seconds', $this->settings->accessTokenTtl)));
    }

    private function findRefresh(#[SensitiveParameter] string $secret): ?Token
    {
        if (!str_starts_with($secret, self::REFRESH_PREFIX)) {
            return null;
        }
        $row = $this->database->findOne(Schema::TOKENS, ['token_hash' => $this->pepper->hash(self::PEPPER_CONTEXT, $secret)]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * A refresh token by its hash, or an access token by the `jti` of a JWT this server signed.
     */
    private function lookup(#[SensitiveParameter] string $token): ?Token
    {
        if (str_starts_with($token, self::REFRESH_PREFIX)) {
            return $this->findRefresh($token);
        }
        try {
            $claims = $this->jwt->verify($token, self::TYP)['claims'];
        } catch (OAuthException) {
            return null;
        }

        return is_string($claims['jti'] ?? null) ? $this->find($claims['jti']) : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function row(Token $token): array
    {
        return [
            'id' => $token->id,
            'kind' => $token->kind,
            'token_hash' => $token->tokenHash,
            'client_id' => $token->clientId,
            'user_id' => $token->userId,
            'organization_id' => $token->organizationId,
            'scopes' => json_encode($token->scopes, JSON_THROW_ON_ERROR),
            'family_id' => $token->familyId,
            'resource' => $token->resource,
            'dpop_jkt' => $token->dpopJkt,
            'actor' => $token->actor === null ? null : json_encode($token->actor, JSON_THROW_ON_ERROR),
            'auth_time' => $token->authTime,
            'expires_at' => $token->expiresAt,
            'revoked_at' => $token->revokedAt,
            'created_at' => $token->createdAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Token
    {
        $token = new Token();
        $token->id = (string) $row['id'];
        $token->kind = (string) $row['kind'];
        $token->tokenHash = self::nullable($row['token_hash'] ?? null);
        $token->clientId = (string) $row['client_id'];
        $token->userId = self::nullable($row['user_id'] ?? null);
        $token->organizationId = self::nullable($row['organization_id'] ?? null);
        $scopes = is_string($row['scopes'] ?? null) ? json_decode($row['scopes'], true) : $row['scopes'];
        $token->scopes = is_array($scopes) ? array_values(array_filter($scopes, is_string(...))) : [];
        $token->familyId = self::nullable($row['family_id'] ?? null);
        $token->resource = self::nullable($row['resource'] ?? null);
        $token->dpopJkt = self::nullable($row['dpop_jkt'] ?? null);
        $actor = is_string($row['actor'] ?? null) ? json_decode($row['actor'], true) : ($row['actor'] ?? null);
        $token->actor = is_array($actor) ? $actor : null;
        $token->authTime = ($row['auth_time'] ?? null) === null ? null : (int) $row['auth_time'];
        $token->expiresAt = self::datetime($row['expires_at']) ?? new DateTimeImmutable();
        $token->revokedAt = self::datetime($row['revoked_at'] ?? null);
        $token->createdAt = self::datetime($row['created_at']) ?? new DateTimeImmutable();

        return $token;
    }

    private static function nullable(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private static function datetime(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}

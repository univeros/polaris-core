<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\Model\Code;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_values;
use function hash;
use function hash_equals;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function preg_match;
use function random_bytes;
use function sprintf;

use const JSON_THROW_ON_ERROR;

/**
 * The authorization codes: minted for a decided request, stored as keyed hashes, spent once by an
 * update conditioned on `used_at IS NULL`, and checked against the client, the redirect URI and the
 * PKCE verifier (S256 only) at the token endpoint.
 */
final class Codes
{
    private const string PEPPER_CONTEXT = 'oauth_code';

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Pepper $pepper,
        private readonly Settings $settings,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param list<string> $scopes
     * @return string the code
     */
    public function issue(Client $client, string $userId, ?string $organizationId, array $scopes, string $redirectUri, string $codeChallenge, ?string $nonce, ?string $resource, ?string $dpopJkt, ?int $authTime): string
    {
        $now = $this->clock->now();
        $code = Jwt::base64UrlEncode(random_bytes(32));
        $this->database->insert(Schema::CODES, [
            'id' => Uuid::v7()->toRfc4122(),
            'code_hash' => $this->pepper->hash(self::PEPPER_CONTEXT, $code),
            'client_id' => $client->clientId,
            'user_id' => $userId,
            'organization_id' => $organizationId,
            'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
            'redirect_uri' => $redirectUri,
            'code_challenge' => $codeChallenge,
            'nonce' => $nonce,
            'resource' => $resource,
            'dpop_jkt' => $dpopJkt,
            'auth_time' => $authTime,
            'expires_at' => $now->modify(sprintf('+%d seconds', $this->settings->codeTtl)),
            'used_at' => null,
            'created_at' => $now,
        ]);

        return $code;
    }

    /**
     * Spends the code for the client, redirect URI and verifier it was issued against.
     *
     * @throws OAuthException `invalid_grant`
     * @throws CodeReused the code was spent before: the caller revokes the family it issued
     */
    public function consume(#[SensitiveParameter] string $code, Client $client, ?string $redirectUri, ?string $verifier): Code
    {
        $row = $this->database->findOne(Schema::CODES, ['code_hash' => $this->pepper->hash(self::PEPPER_CONTEXT, $code)]);
        if ($row === null) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The authorization code is unknown.');
        }
        $stored = self::hydrate($row);
        $now = $this->clock->now();
        if ($stored->usedAt !== null) {
            // RFC 9700 §4.5: a code presented twice is a leak; the tokens it produced go with it.
            throw new CodeReused($stored->id);
        }
        if ($stored->clientId !== $client->clientId) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The authorization code was issued to another client.');
        }
        if ($stored->expiresAt <= $now) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The authorization code expired.');
        }
        if ($redirectUri !== null && $redirectUri !== $stored->redirectUri) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'redirect_uri does not match the authorization request.');
        }
        if (!is_string($verifier) || preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $verifier) !== 1 || !hash_equals($stored->codeChallenge, Jwt::base64UrlEncode(hash('sha256', $verifier, true)))) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'code_verifier does not match the code challenge.');
        }
        if ($this->database->update(Schema::CODES, ['id' => $stored->id, 'used_at' => null], ['used_at' => $now]) !== 1) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The authorization code was already used.');
        }
        $stored->usedAt = $now;

        return $stored;
    }

    public function prune(): int
    {
        return $this->database->delete(Schema::CODES, ['expires_at' => Condition::lt($this->clock->now())]);
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Code
    {
        $code = new Code();
        $code->id = (string) $row['id'];
        $code->codeHash = (string) $row['code_hash'];
        $code->clientId = (string) $row['client_id'];
        $code->userId = (string) $row['user_id'];
        $code->organizationId = self::nullable($row['organization_id'] ?? null);
        $scopes = is_string($row['scopes'] ?? null) ? json_decode($row['scopes'], true) : $row['scopes'];
        $code->scopes = is_array($scopes) ? array_values(array_filter($scopes, is_string(...))) : [];
        $code->redirectUri = (string) $row['redirect_uri'];
        $code->codeChallenge = (string) $row['code_challenge'];
        $code->nonce = self::nullable($row['nonce'] ?? null);
        $code->resource = self::nullable($row['resource'] ?? null);
        $code->dpopJkt = self::nullable($row['dpop_jkt'] ?? null);
        $code->authTime = ($row['auth_time'] ?? null) === null ? null : (int) $row['auth_time'];
        $code->expiresAt = $row['expires_at'] instanceof DateTimeImmutable ? $row['expires_at'] : new DateTimeImmutable((string) $row['expires_at']);
        $code->usedAt = ($row['used_at'] ?? null) === null ? null : ($row['used_at'] instanceof DateTimeImmutable ? $row['used_at'] : new DateTimeImmutable((string) $row['used_at']));
        $code->createdAt = $row['created_at'] instanceof DateTimeImmutable ? $row['created_at'] : new DateTimeImmutable((string) $row['created_at']);

        return $code;
    }

    private static function nullable(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Identity\EmailNormalizer;
use Polaris\Model\User;
use Polaris\OAuth\Model\CibaRequest;
use Polaris\OAuth\Model\Client;
use Polaris\Repository\UserRepository;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_values;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function mb_strlen;
use function preg_match;
use function sprintf;

use const JSON_THROW_ON_ERROR;

/**
 * Client-initiated backchannel authentication (OpenID CIBA, poll mode): a client names a user by
 * email and asks them to approve a sign-in with a short binding message; the user sees the request
 * from their own session (`GET /oauth2/ciba/pending`) and decides; the client polls the token
 * endpoint with `auth_req_id`. The host may push the request through its own channel from the
 * `oauth.ciba_requested` event.
 */
final class Ciba
{
    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly UserRepository $users,
        private readonly Settings $settings,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param list<string> $scopes
     * @return array{array<string, mixed>, CibaRequest} the CIBA §7.3 response, and the request
     * @throws OAuthException `unauthorized_client`, `unknown_user_id`, `invalid_request`
     */
    public function request(Client $client, array $scopes, ?string $loginHint, ?string $bindingMessage, ?string $resource): array
    {
        if (!$client->allowsGrant(Clients::GRANT_CIBA)) {
            throw new OAuthException(OAuthException::UNAUTHORIZED_CLIENT, 'The client may not use the backchannel grant.');
        }
        if ($loginHint === null) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'login_hint (the user\'s email) is required.');
        }
        if ($bindingMessage !== null && (mb_strlen($bindingMessage) > 160 || preg_match('/^[\p{L}\p{N}\p{P}\p{Zs}]+$/u', $bindingMessage) !== 1)) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'binding_message is short plain text (at most 160 characters).');
        }
        $user = $this->users->findOneBy(['email' => EmailNormalizer::normalize($loginHint)]);
        if (!$user instanceof User || $user->status !== User::STATUS_ACTIVE) {
            throw new OAuthException(OAuthException::UNKNOWN_USER_ID, 'No user answers to that hint.');
        }
        $now = $this->clock->now();
        $request = new CibaRequest();
        $request->id = Uuid::v7()->toRfc4122();
        $request->clientId = $client->clientId;
        $request->userId = $user->id;
        $request->scopes = $scopes;
        $request->bindingMessage = $bindingMessage;
        $request->resource = $resource;
        $request->expiresAt = $now->modify(sprintf('+%d seconds', $this->settings->cibaTtl));
        $request->createdAt = $now;
        $this->database->insert(Schema::CIBA_REQUESTS, [
            'id' => $request->id,
            'client_id' => $request->clientId,
            'user_id' => $request->userId,
            'organization_id' => null,
            'scopes' => json_encode($scopes, JSON_THROW_ON_ERROR),
            'binding_message' => $bindingMessage,
            'resource' => $resource,
            'status' => CibaRequest::STATUS_PENDING,
            'auth_time' => null,
            'last_polled_at' => null,
            'expires_at' => $request->expiresAt,
            'created_at' => $now,
        ]);

        return [['auth_req_id' => $request->id, 'expires_in' => $this->settings->cibaTtl, 'interval' => $this->settings->pollInterval], $request];
    }

    /**
     * The user's pending requests, newest first.
     *
     * @return list<CibaRequest>
     */
    public function pending(string $userId): array
    {
        $requests = [];
        $now = $this->clock->now();
        foreach ($this->database->findMany(Schema::CIBA_REQUESTS, ['user_id' => $userId, 'status' => CibaRequest::STATUS_PENDING], ['id' => 'desc']) as $row) {
            $request = self::hydrate($row);
            if ($request->expiresAt > $now) {
                $requests[] = $request;
            }
        }

        return $requests;
    }

    /**
     * @throws OAuthException `not_found`, `invalid_grant`
     */
    public function decide(string $id, string $userId, bool $approve, ?string $organizationId, ?int $authTime): CibaRequest
    {
        $row = $this->database->findOne(Schema::CIBA_REQUESTS, ['id' => $id, 'user_id' => $userId]);
        $request = $row === null ? null : self::hydrate($row);
        if ($request === null || $request->expiresAt <= $this->clock->now()) {
            throw new OAuthException(OAuthException::NOT_FOUND, 'No such pending request.', 404);
        }
        $status = $approve ? CibaRequest::STATUS_APPROVED : CibaRequest::STATUS_DENIED;
        if ($this->database->update(Schema::CIBA_REQUESTS, ['id' => $request->id, 'status' => CibaRequest::STATUS_PENDING], ['status' => $status, 'organization_id' => $organizationId, 'auth_time' => $authTime]) !== 1) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The request was already decided.', 409);
        }
        $request->status = $status;
        $request->organizationId = $organizationId;
        $request->authTime = $authTime;

        return $request;
    }

    /**
     * The client's poll at the token endpoint.
     *
     * @throws OAuthException `authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `invalid_grant`
     */
    public function poll(string $authReqId, Client $client): CibaRequest
    {
        $row = preg_match('/^[0-9a-f-]{36}$/', $authReqId) === 1 ? $this->database->findOne(Schema::CIBA_REQUESTS, ['id' => $authReqId]) : null;
        $request = $row === null ? null : self::hydrate($row);
        if ($request === null || $request->clientId !== $client->clientId) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The auth_req_id is unknown.');
        }
        $now = $this->clock->now();
        if ($request->expiresAt <= $now) {
            throw new OAuthException(OAuthException::EXPIRED_TOKEN, 'The request expired; ask again.');
        }
        $tooSoon = $request->lastPolledAt !== null && $now->getTimestamp() - $request->lastPolledAt->getTimestamp() < $this->settings->pollInterval;
        $this->database->update(Schema::CIBA_REQUESTS, ['id' => $request->id], ['last_polled_at' => $now]);
        if ($tooSoon) {
            throw new OAuthException(OAuthException::SLOW_DOWN, sprintf('Poll every %d seconds.', $this->settings->pollInterval));
        }
        return match ($request->status) {
            CibaRequest::STATUS_PENDING => throw new OAuthException(OAuthException::AUTHORIZATION_PENDING, 'The user has not decided yet.'),
            CibaRequest::STATUS_DENIED => throw new OAuthException(OAuthException::ACCESS_DENIED, 'The user refused.'),
            CibaRequest::STATUS_APPROVED => $this->spend($request),
            default => throw new OAuthException(OAuthException::INVALID_GRANT, 'The request was already used.'),
        };
    }

    public function prune(): int
    {
        return $this->database->delete(Schema::CIBA_REQUESTS, ['expires_at' => Condition::lt($this->clock->now())]);
    }

    private function spend(CibaRequest $request): CibaRequest
    {
        if ($this->database->update(Schema::CIBA_REQUESTS, ['id' => $request->id, 'status' => CibaRequest::STATUS_APPROVED], ['status' => CibaRequest::STATUS_USED]) !== 1) {
            throw new OAuthException(OAuthException::INVALID_GRANT, 'The request was already used.');
        }
        $request->status = CibaRequest::STATUS_USED;

        return $request;
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): CibaRequest
    {
        $request = new CibaRequest();
        $request->id = (string) $row['id'];
        $request->clientId = (string) $row['client_id'];
        $request->userId = (string) $row['user_id'];
        $request->organizationId = is_string($row['organization_id'] ?? null) && $row['organization_id'] !== '' ? $row['organization_id'] : null;
        $scopes = is_string($row['scopes'] ?? null) ? json_decode($row['scopes'], true) : $row['scopes'];
        $request->scopes = is_array($scopes) ? array_values(array_filter($scopes, is_string(...))) : [];
        $request->bindingMessage = is_string($row['binding_message'] ?? null) && $row['binding_message'] !== '' ? $row['binding_message'] : null;
        $request->resource = is_string($row['resource'] ?? null) && $row['resource'] !== '' ? $row['resource'] : null;
        $request->status = (string) $row['status'];
        $request->authTime = ($row['auth_time'] ?? null) === null ? null : (int) $row['auth_time'];
        $request->lastPolledAt = self::datetime($row['last_polled_at'] ?? null);
        $request->expiresAt = self::datetime($row['expires_at']) ?? new DateTimeImmutable();
        $request->createdAt = self::datetime($row['created_at']) ?? new DateTimeImmutable();

        return $request;
    }

    private static function datetime(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}

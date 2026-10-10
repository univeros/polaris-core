<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Http;

use DateTimeImmutable;
use Exception;
use Polaris\ApiKeys\ApiKeyException;
use Polaris\ApiKeys\Keys;
use Polaris\ApiKeys\Model\ApiKey;
use Polaris\Authorization\Gate;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function is_string;
use function trim;

/**
 * What every API-key route shares: the problem documents, the owner a request names (the caller, or
 * an organization the caller may manage keys for), the key a path names when the caller may manage it.
 */
abstract class ApiKeysEndpoint extends Endpoint
{
    /** The permission a member needs to manage an organization's keys. */
    public const string ORGANIZATION_PERMISSION = PermissionCatalog::ORG_UPDATE;

    protected function refuse(ApiKeyException $exception): Result
    {
        return match ($exception->reason) {
            ApiKeyException::NOT_FOUND => $this->problem(404, 'api-keys/not_found', 'Not found', $exception->detail),
            ApiKeyException::FORBIDDEN => $this->problem(403, 'api-keys/forbidden', 'Forbidden', $exception->detail),
            ApiKeyException::TOO_MANY => $this->problem(409, 'api-keys/too_many', 'Too many keys', $exception->detail),
            ApiKeyException::PERMISSION_NOT_HELD => $this->problem(403, 'api-keys/permission_not_held', 'Permission not held', $exception->detail),
            default => $this->problem(422, 'api-keys/invalid_input', 'Invalid input', $exception->detail, ['errors' => [$exception->detail]]),
        };
    }

    /**
     * The owner of the keys a request is about: the caller, or the organization `organization_id`
     * names when it is the caller's active organization and the caller may update it.
     *
     * @return array{string, string, string|null} owner type, owner id, organization context
     */
    protected function owner(Input $input, TokenInterface $token, Gate $gate): array
    {
        $organizationId = self::text($input, 'organization_id');
        if ($organizationId === null) {
            return [ApiKey::OWNER_USER, $this->actorId($token), $this->actorOrg($token)];
        }
        if ($organizationId !== $this->actorOrg($token) || !$gate->allows($token, self::ORGANIZATION_PERMISSION)) {
            throw new ApiKeyException(ApiKeyException::FORBIDDEN, 'Managing an organization\'s keys needs it as your active organization and the org.update permission in it.');
        }

        return [ApiKey::OWNER_ORGANIZATION, $organizationId, $organizationId];
    }

    /**
     * The key `{id}` names when the caller may manage it: their own, or their active organization's
     * when they may update that organization.
     */
    protected function manageable(Keys $keys, Input $input, TokenInterface $token, Gate $gate): ApiKey
    {
        $key = $keys->find((string) $input->get('id'));
        if (!$key instanceof ApiKey || $key->revokedAt !== null) {
            throw new ApiKeyException(ApiKeyException::NOT_FOUND, 'The key does not exist.');
        }
        $own = $key->ownerType === ApiKey::OWNER_USER && $key->ownerId === $this->actorId($token);
        $organization = $key->ownerType === ApiKey::OWNER_ORGANIZATION && $key->ownerId === $this->actorOrg($token) && $gate->allows($token, self::ORGANIZATION_PERMISSION);
        if (!$own && !$organization) {
            throw new ApiKeyException(ApiKeyException::NOT_FOUND, 'The key does not exist.');
        }

        return $key;
    }

    /**
     * The permissions the caller holds in the key's organization context, which bound the key's: the
     * caller's active organization must be that context (switch to it to change a key's permissions).
     *
     * @return list<string>
     */
    protected function held(TokenInterface $token, Gate $gate, ?string $organizationId): array
    {
        if ($organizationId !== $this->actorOrg($token)) {
            throw new ApiKeyException(ApiKeyException::FORBIDDEN, 'The key acts in another organization than your active one; switch to it to change its permissions.');
        }

        return $gate->authority($token)->scope;
    }

    protected static function text(Input $input, string $field): ?string
    {
        $value = $input->get($field);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /**
     * @return DateTimeImmutable|null|false false when the value is not a date
     */
    protected static function datetime(mixed $value): DateTimeImmutable|null|false
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (!is_string($value)) {
            return false;
        }
        try {
            return new DateTimeImmutable($value);
        } catch (Exception) {
            return false;
        }
    }
}

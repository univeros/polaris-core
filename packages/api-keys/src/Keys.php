<?php

declare(strict_types=1);

namespace Polaris\ApiKeys;

use DateTimeImmutable;
use Polaris\ApiKeys\Model\ApiKey;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;

use function array_fill_keys;
use function array_filter;
use function array_is_list;
use function array_unique;
use function array_values;
use function base64_encode;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use function mb_strlen;
use function preg_match;
use function random_bytes;
use function rtrim;
use function sprintf;
use function str_starts_with;
use function strlen;
use function strtr;
use function substr;
use function trim;

use const JSON_THROW_ON_ERROR;

/**
 * The API keys: minted as `pk_<environment>_` plus 256 random bits, stored as a keyed hash under the
 * `api_key` pepper context, shown once; checked at each use for revocation, expiry and the rotation
 * grace; rotated by minting a successor and keeping the predecessor for the grace window.
 */
final class Keys
{
    public const string PEPPER_CONTEXT = 'api_key';
    private const int SECRET_BYTES = 32;
    private const int LAST_USED_RESOLUTION = 60;
    private const int NAME_MAX = 80;
    private const int METADATA_MAX_BYTES = 4096;

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Pepper $pepper,
        private readonly PermissionCatalog $catalog,
        private readonly Settings $settings,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param array<mixed> $permissions what the key may do, each held by the owner (`$held`)
     * @param list<string> $held the permissions the caller holds in the key's organization context
     * @param array<mixed>|null $rateLimit `{window, max}`
     * @param array<mixed> $metadata
     */
    public function create(string $ownerType, string $ownerId, ?string $organizationId, string $createdBy, string $name, array $permissions, array $held, ?string $environment = null, ?array $rateLimit = null, ?DateTimeImmutable $expiresAt = null, array $metadata = []): IssuedKey
    {
        $now = $this->clock->now();
        $environment ??= $this->settings->environment;
        if (!in_array($environment, [Settings::LIVE, Settings::TEST], true)) {
            throw new ApiKeyException(ApiKeyException::INVALID_INPUT, 'environment must be live or test.');
        }
        if ($this->database->count(Schema::KEYS, ['owner_type' => $ownerType, 'owner_id' => $ownerId, 'revoked_at' => null]) >= $this->settings->maxPerOwner) {
            throw new ApiKeyException(ApiKeyException::TOO_MANY, sprintf('An owner may hold at most %d keys; revoke one first.', $this->settings->maxPerOwner));
        }
        $key = new ApiKey();
        $key->id = Uuid::v7()->toRfc4122();
        $key->ownerType = $ownerType;
        $key->ownerId = $ownerId;
        $key->organizationId = $organizationId;
        $key->createdBy = $createdBy;
        $key->name = self::name($name);
        $key->environment = $environment;
        $key->permissions = $this->permissions($permissions, $held);
        [$key->rateLimitWindow, $key->rateLimitMax] = $this->rateLimit($rateLimit);
        $key->expiresAt = self::expiry($expiresAt, $now);
        $key->metadata = self::metadata($metadata);
        $key->createdAt = $now;
        $key->updatedAt = $now;
        $secret = $this->secret($key);
        $this->database->insert(Schema::KEYS, $this->row($key));

        return new IssuedKey($key, $secret);
    }

    /**
     * The key behind a presented secret when it is live: not revoked, not expired, and (after a
     * rotation) within its grace window; its `last_used_at` is stamped at most once a minute.
     */
    public function authenticate(#[SensitiveParameter] string $secret): ?ApiKey
    {
        if (!str_starts_with($secret, 'pk_') || strlen($secret) > 80) {
            return null;
        }
        $row = $this->database->findOne(Schema::KEYS, ['key_hash' => $this->pepper->hash(self::PEPPER_CONTEXT, $secret)]);
        if ($row === null) {
            return null;
        }
        $key = self::hydrate($row);
        $now = $this->clock->now();
        if ($key->revokedAt !== null || ($key->expiresAt !== null && $key->expiresAt <= $now) || ($key->graceUntil !== null && $key->graceUntil <= $now)) {
            return null;
        }
        if ($key->lastUsedAt === null || $now->getTimestamp() - $key->lastUsedAt->getTimestamp() >= self::LAST_USED_RESOLUTION) {
            $key->lastUsedAt = $now;
            $this->database->update(Schema::KEYS, ['id' => $key->id], ['last_used_at' => $now]);
        }

        return $key;
    }

    public function find(string $id): ?ApiKey
    {
        $row = $this->database->findOne(Schema::KEYS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * The owner's keys that are not revoked, newest first.
     *
     * @return list<ApiKey>
     */
    public function forOwner(string $ownerType, string $ownerId): array
    {
        $keys = [];
        foreach ($this->database->findMany(Schema::KEYS, ['owner_type' => $ownerType, 'owner_id' => $ownerId, 'revoked_at' => null], ['id' => 'desc']) as $row) {
            $keys[] = self::hydrate($row);
        }

        return $keys;
    }

    /**
     * @param array<mixed>|null $permissions
     * @param list<string> $held
     * @param array<mixed>|null|false $rateLimit false leaves it, null clears it
     * @param array<mixed>|null $metadata
     * @return list<string> what changed
     */
    public function update(ApiKey $key, array $held, ?string $name = null, ?array $permissions = null, array|null|false $rateLimit = false, DateTimeImmutable|null|false $expiresAt = false, ?array $metadata = null): array
    {
        $now = $this->clock->now();
        $changes = [];
        $data = ['updated_at' => $now];
        if ($name !== null) {
            $key->name = self::name($name);
            $data['name'] = $key->name;
            $changes[] = 'name';
        }
        if ($permissions !== null) {
            $key->permissions = $this->permissions($permissions, $held);
            $data['permissions'] = json_encode($key->permissions, JSON_THROW_ON_ERROR);
            $changes[] = 'permissions';
        }
        if ($rateLimit !== false) {
            [$key->rateLimitWindow, $key->rateLimitMax] = $this->rateLimit($rateLimit);
            $data['rate_limit_window'] = $key->rateLimitWindow;
            $data['rate_limit_max'] = $key->rateLimitMax;
            $changes[] = 'rate_limit';
        }
        if ($expiresAt !== false) {
            $key->expiresAt = self::expiry($expiresAt, $now);
            $data['expires_at'] = $key->expiresAt;
            $changes[] = 'expires_at';
        }
        if ($metadata !== null) {
            $key->metadata = self::metadata($metadata);
            $data['metadata'] = json_encode($key->metadata, JSON_THROW_ON_ERROR);
            $changes[] = 'metadata';
        }
        $key->updatedAt = $now;
        $this->database->update(Schema::KEYS, ['id' => $key->id], $data);

        return $changes;
    }

    /**
     * A successor with a new secret and the same owner, name, permissions, limit, expiry and
     * metadata; the predecessor answers for the grace window, then stops. A key already rotated is
     * refused: its successor is the one to rotate.
     */
    public function rotate(ApiKey $key): IssuedKey
    {
        if ($key->graceUntil !== null) {
            throw new ApiKeyException(ApiKeyException::FORBIDDEN, 'This key was already rotated; rotate its successor.');
        }
        $now = $this->clock->now();
        $successor = clone $key;
        $successor->id = Uuid::v7()->toRfc4122();
        $successor->rotatedFromId = $key->id;
        $successor->graceUntil = null;
        $successor->lastUsedAt = null;
        $successor->createdAt = $now;
        $successor->updatedAt = $now;
        $secret = $this->secret($successor);
        $graceUntil = $now->modify(sprintf('+%d seconds', $this->settings->rotationGrace));
        $this->database->transaction(function () use ($key, $successor, $graceUntil, $now): void {
            $this->database->insert(Schema::KEYS, $this->row($successor));
            $this->database->update(Schema::KEYS, ['id' => $key->id], ['grace_until' => $graceUntil, 'updated_at' => $now]);
        });
        $key->graceUntil = $graceUntil;
        $key->updatedAt = $now;

        return new IssuedKey($successor, $secret);
    }

    public function revoke(ApiKey $key): void
    {
        $now = $this->clock->now();
        $key->revokedAt = $now;
        $key->updatedAt = $now;
        $this->database->update(Schema::KEYS, ['id' => $key->id], ['revoked_at' => $now, 'updated_at' => $now]);
    }

    /**
     * An erased user leaves no key behind: their own, and the organization keys they act for.
     */
    public function deleteForUser(string $userId): void
    {
        $this->database->delete(Schema::KEYS, ['owner_type' => ApiKey::OWNER_USER, 'owner_id' => $userId]);
        $this->database->delete(Schema::KEYS, ['created_by' => $userId]);
    }

    public function deleteForOrganization(string $organizationId): void
    {
        $this->database->delete(Schema::KEYS, ['organization_id' => $organizationId]);
    }

    private function secret(ApiKey $key): string
    {
        $secret = Settings::prefix($key->environment) . rtrim(strtr(base64_encode(random_bytes(self::SECRET_BYTES)), '+/', '-_'), '=');
        $key->hint = substr($secret, -4);
        $key->keyHash = $this->pepper->hash(self::PEPPER_CONTEXT, $secret);

        return $secret;
    }

    private static function name(string $name): string
    {
        $name = trim($name);
        if ($name === '' || mb_strlen($name) > self::NAME_MAX) {
            throw new ApiKeyException(ApiKeyException::INVALID_INPUT, sprintf('name is required and at most %d characters.', self::NAME_MAX));
        }

        return $name;
    }

    /**
     * Each permission must exist in the catalog and be held by the owner.
     *
     * @param array<mixed> $permissions
     * @param list<string> $held
     * @return list<string>
     */
    private function permissions(array $permissions, array $held): array
    {
        if (!array_is_list($permissions)) {
            throw new ApiKeyException(ApiKeyException::INVALID_INPUT, 'permissions must be a list of permission names.');
        }
        $known = $this->catalog->permissions();
        $granted = array_fill_keys($held, true);
        $out = [];
        foreach (array_unique($permissions) as $permission) {
            if (!is_string($permission) || preg_match('/^[a-z0-9_]+(\.[a-z0-9_]+)+$/', $permission) !== 1 || !isset($known[$permission])) {
                throw new ApiKeyException(ApiKeyException::INVALID_INPUT, sprintf('Unknown permission "%s".', is_string($permission) ? $permission : '?'));
            }
            if (!isset($granted[$permission])) {
                throw new ApiKeyException(ApiKeyException::PERMISSION_NOT_HELD, sprintf('You do not hold "%s" in this organization, so the key cannot either.', $permission));
            }
            $out[] = $permission;
        }

        return $out;
    }

    /**
     * @param array<mixed>|null $rateLimit
     * @return array{int|null, int|null}
     */
    private function rateLimit(?array $rateLimit): array
    {
        if ($rateLimit === null) {
            return [null, null];
        }
        $window = $rateLimit['window'] ?? null;
        $max = $rateLimit['max'] ?? null;
        if (!is_int($window) || !is_int($max) || $window < 1 || $window > $this->settings->maxRateLimitWindow || $max < 1) {
            throw new ApiKeyException(ApiKeyException::INVALID_INPUT, sprintf('rate_limit needs window (1 to %d seconds) and max (at least 1).', $this->settings->maxRateLimitWindow));
        }

        return [$window, $max];
    }

    private static function expiry(?DateTimeImmutable $expiresAt, DateTimeImmutable $now): ?DateTimeImmutable
    {
        if ($expiresAt !== null && $expiresAt <= $now) {
            throw new ApiKeyException(ApiKeyException::INVALID_INPUT, 'expires_at must be in the future.');
        }

        return $expiresAt;
    }

    /**
     * @param array<mixed> $metadata
     * @return array<string, mixed>
     */
    private static function metadata(array $metadata): array
    {
        if ($metadata !== [] && array_is_list($metadata)) {
            throw new ApiKeyException(ApiKeyException::INVALID_INPUT, 'metadata must be an object.');
        }
        if (strlen(json_encode($metadata, JSON_THROW_ON_ERROR)) > self::METADATA_MAX_BYTES) {
            throw new ApiKeyException(ApiKeyException::INVALID_INPUT, sprintf('metadata is limited to %d bytes.', self::METADATA_MAX_BYTES));
        }
        $out = [];
        foreach ($metadata as $name => $value) {
            $out[(string) $name] = $value;
        }

        return $out;
    }

    /**
     * @return array<string, mixed>
     */
    private function row(ApiKey $key): array
    {
        return [
            'id' => $key->id,
            'owner_type' => $key->ownerType,
            'owner_id' => $key->ownerId,
            'organization_id' => $key->organizationId,
            'created_by' => $key->createdBy,
            'name' => $key->name,
            'environment' => $key->environment,
            'hint' => $key->hint,
            'key_hash' => $key->keyHash,
            'permissions' => json_encode($key->permissions, JSON_THROW_ON_ERROR),
            'rate_limit_window' => $key->rateLimitWindow,
            'rate_limit_max' => $key->rateLimitMax,
            'metadata' => json_encode($key->metadata, JSON_THROW_ON_ERROR),
            'rotated_from_id' => $key->rotatedFromId,
            'grace_until' => $key->graceUntil,
            'expires_at' => $key->expiresAt,
            'last_used_at' => $key->lastUsedAt,
            'revoked_at' => $key->revokedAt,
            'created_at' => $key->createdAt,
            'updated_at' => $key->updatedAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): ApiKey
    {
        $key = new ApiKey();
        $key->id = (string) $row['id'];
        $key->ownerType = (string) $row['owner_type'];
        $key->ownerId = (string) $row['owner_id'];
        $key->organizationId = self::nullable($row['organization_id'] ?? null);
        $key->createdBy = (string) $row['created_by'];
        $key->name = (string) $row['name'];
        $key->environment = (string) $row['environment'];
        $key->hint = (string) $row['hint'];
        $key->keyHash = (string) $row['key_hash'];
        $permissions = self::json($row['permissions'] ?? null);
        $key->permissions = array_values(array_filter($permissions, is_string(...)));
        $key->rateLimitWindow = ($row['rate_limit_window'] ?? null) === null ? null : (int) $row['rate_limit_window'];
        $key->rateLimitMax = ($row['rate_limit_max'] ?? null) === null ? null : (int) $row['rate_limit_max'];
        $key->metadata = self::json($row['metadata'] ?? null);
        $key->rotatedFromId = self::nullable($row['rotated_from_id'] ?? null);
        $key->graceUntil = self::datetime($row['grace_until'] ?? null);
        $key->expiresAt = self::datetime($row['expires_at'] ?? null);
        $key->lastUsedAt = self::datetime($row['last_used_at'] ?? null);
        $key->revokedAt = self::datetime($row['revoked_at'] ?? null);
        $key->createdAt = self::datetime($row['created_at']) ?? new DateTimeImmutable();
        $key->updatedAt = self::datetime($row['updated_at']) ?? $key->createdAt;

        return $key;
    }

    private static function nullable(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return array<mixed>
     */
    private static function json(mixed $value): array
    {
        $decoded = is_string($value) ? json_decode($value, true) : $value;

        return is_array($decoded) ? $decoded : [];
    }

    private static function datetime(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}

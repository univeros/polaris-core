<?php

declare(strict_types=1);

namespace Polaris\Scim;

use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Model\MembershipRole;
use Polaris\Model\Role;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Model\Resource;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

use function array_slice;
use function count;
use function in_array;
use function is_array;
use function is_string;
use function mb_strlen;
use function preg_replace;
use function strtolower;
use function trim;
use function usort;

use const DATE_ATOM;

/**
 * SCIM Groups onto the organization's roles: `displayName` is the role name, `members` the memberships
 * holding it. A Group the directory creates is a custom role with an empty permission set until an
 * organization admin fills it; a built-in role (owner, admin, member) can be listed and given members but
 * neither renamed nor deleted.
 */
final class Groups
{
    public const string SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
    /** The roles every organization starts with: listed and given members, never renamed or deleted here. */
    private const array PROTECTED = ['owner', 'admin', 'member'];

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly Resources $resources,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @return array{total: int, resources: list<array<string, mixed>>}
     */
    public function list(Connection $connection, Filter $filter, int $startIndex, int $count, string $location): array
    {
        $matches = [];
        foreach ($this->database->findMany('auth_roles', ['organization_id' => $connection->organizationId], ['id' => 'asc']) as $row) {
            $resource = $this->resource($connection, $row, $location);
            if ($filter->matches(['id' => $resource['id'], 'displayname' => $resource['displayName'], 'externalid' => $resource['externalId'] ?? ''])) {
                $matches[] = $resource;
            }
        }

        return ['total' => count($matches), 'resources' => array_slice($matches, $startIndex - 1, $count)];
    }

    /**
     * @return array<string, mixed> the role row
     * @throws ScimError
     */
    public function find(Connection $connection, string $id): array
    {
        $role = $this->database->findOne('auth_roles', ['id' => $id, 'organization_id' => $connection->organizationId]);

        return $role ?? throw ScimError::notFound('Group');
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed> the role row
     * @throws ScimError
     */
    public function create(Connection $connection, array $body): array
    {
        $name = self::name($body);
        $slug = self::slug($name);
        if ($this->database->findOne('auth_roles', ['organization_id' => $connection->organizationId, 'slug' => $slug]) !== null) {
            throw ScimError::conflict('A group with this displayName exists.');
        }
        $now = $this->clock->now();
        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = $connection->organizationId;
        $role->name = $name;
        $role->slug = $slug;
        $role->description = 'Provisioned by SCIM';
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $this->unitOfWork->persist($role);
        $this->unitOfWork->flush();
        $this->resources->setExternalId($connection, Resource::GROUP, $role->id, self::externalId($body));
        $this->setMembers($connection, $role->id, self::memberIds($body['members'] ?? []));

        return $this->find($connection, $role->id);
    }

    /**
     * PUT: the name (custom roles only) and the whole member list.
     *
     * @param array<string, mixed> $role
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     * @throws ScimError
     */
    public function replace(Connection $connection, array $role, array $body): array
    {
        $this->rename($role, self::name($body));
        $this->resources->setExternalId($connection, Resource::GROUP, (string) $role['id'], self::externalId($body));
        $this->setMembers($connection, (string) $role['id'], self::memberIds($body['members'] ?? []));

        return $this->find($connection, (string) $role['id']);
    }

    /**
     * PATCH: `displayName`, `externalId`, and `members` added, removed or replaced.
     *
     * @param array<string, mixed> $role
     * @param list<array{string, string|null, mixed}> $operations
     * @return array<string, mixed>
     * @throws ScimError
     */
    public function patch(Connection $connection, array $role, array $operations): array
    {
        $roleId = (string) $role['id'];
        foreach ($operations as [$op, $path, $value]) {
            $name = Patch::scalar([$op, $path, $value], 'displayName');
            if (is_string($name)) {
                $this->rename($role, self::name(['displayName' => $name]));
            }
            $externalId = Patch::scalar([$op, $path, $value], 'externalId');
            if (is_string($externalId)) {
                $this->resources->setExternalId($connection, Resource::GROUP, $roleId, trim($externalId));
            }
            $lower = $path === null ? null : strtolower(Patch::stripUrn($path));
            if ($lower === 'members' || ($path === null && is_array($value) && isset($value['members']))) {
                $ids = self::memberIds($path === null ? $value['members'] : $value);
                match ($op) {
                    'add' => $this->addMembers($connection, $roleId, $ids),
                    'replace' => $this->setMembers($connection, $roleId, $ids),
                    default => $this->removeMembers($connection, $roleId, $ids),
                };
            } elseif ($lower !== null && str_starts_with($lower, 'members[')) {
                if ($op !== 'remove' || preg_match('/members\[value\s+eq\s+"([^"]+)"\]/i', (string) $path, $match) !== 1) {
                    throw ScimError::invalid('Only members[value eq "id"] is supported on remove.', ScimError::INVALID_PATH);
                }
                $this->removeMembers($connection, $roleId, [$match[1]]);
            }
        }

        return $this->find($connection, $roleId);
    }

    /**
     * @param array<string, mixed> $role
     * @throws ScimError
     */
    public function delete(Connection $connection, array $role): void
    {
        if (in_array($role['slug'] ?? null, self::PROTECTED, true)) {
            throw new ScimError(403, 'A built-in role cannot be deleted.', ScimError::MUTABILITY);
        }
        $this->database->delete('auth_membership_roles', ['role_id' => $role['id']]);
        $this->database->delete('auth_role_permissions', ['role_id' => $role['id']]);
        $this->database->delete('auth_roles', ['id' => $role['id']]);
        $this->resources->forget($connection, Resource::GROUP, (string) $role['id']);
    }

    /**
     * @param array<string, mixed> $role
     * @return array<string, mixed>
     */
    public function resource(Connection $connection, array $role, string $location): array
    {
        $members = [];
        foreach ($this->database->findMany('auth_membership_roles', ['role_id' => $role['id']]) as $link) {
            $membership = $this->database->findOne('auth_memberships', ['id' => $link['membership_id'], 'organization_id' => $connection->organizationId]);
            $user = $membership === null ? null : $this->database->findOne('auth_users', ['id' => $membership['user_id']]);
            if ($user !== null) {
                $members[] = ['value' => (string) $user['id'], 'display' => (string) $user['email'], '$ref' => $location . '/Users/' . $user['id']];
            }
        }
        usort($members, static fn(array $a, array $b): int => $a['value'] <=> $b['value']);
        $resource = [
            'schemas' => [self::SCHEMA],
            'id' => (string) $role['id'],
            'displayName' => (string) $role['name'],
            'members' => $members,
            'meta' => ['resourceType' => Resource::GROUP, 'created' => self::datetime($role['created_at']), 'lastModified' => self::datetime($role['updated_at']), 'location' => $location . '/Groups/' . $role['id']],
        ];
        $externalId = $this->resources->externalId($connection, Resource::GROUP, (string) $role['id']);
        if ($externalId !== null) {
            $resource['externalId'] = $externalId;
        }

        return $resource;
    }

    /**
     * @param array<string, mixed> $role
     * @throws ScimError
     */
    private function rename(array $role, string $name): void
    {
        if ($name === (string) $role['name']) {
            return;
        }
        if (in_array($role['slug'] ?? null, self::PROTECTED, true)) {
            throw new ScimError(403, 'A built-in role cannot be renamed.', ScimError::MUTABILITY);
        }
        $this->database->update('auth_roles', ['id' => $role['id']], ['name' => $name, 'updated_at' => $this->clock->now()]);
    }

    /**
     * @param list<string> $userIds
     */
    private function setMembers(Connection $connection, string $roleId, array $userIds): void
    {
        $this->database->delete('auth_membership_roles', ['role_id' => $roleId]);
        $this->addMembers($connection, $roleId, $userIds);
    }

    /**
     * @param list<string> $userIds
     * @throws ScimError
     */
    private function addMembers(Connection $connection, string $roleId, array $userIds): void
    {
        foreach ($userIds as $userId) {
            $membership = $this->database->findOne('auth_memberships', ['user_id' => $userId, 'organization_id' => $connection->organizationId]);
            if ($membership === null) {
                throw ScimError::invalid('Member ' . $userId . ' is not in the organization.');
            }
            if ($this->database->findOne('auth_membership_roles', ['membership_id' => $membership['id'], 'role_id' => $roleId]) !== null) {
                continue;
            }
            $link = new MembershipRole();
            $link->membershipId = (string) $membership['id'];
            $link->roleId = $roleId;
            $this->unitOfWork->persist($link);
        }
        $this->unitOfWork->flush();
    }

    /**
     * @param list<string> $userIds
     */
    private function removeMembers(Connection $connection, string $roleId, array $userIds): void
    {
        foreach ($userIds as $userId) {
            $membership = $this->database->findOne('auth_memberships', ['user_id' => $userId, 'organization_id' => $connection->organizationId]);
            if ($membership !== null) {
                $this->database->delete('auth_membership_roles', ['membership_id' => $membership['id'], 'role_id' => $roleId]);
            }
        }
    }

    /**
     * @return list<string>
     * @throws ScimError
     */
    private static function memberIds(mixed $members): array
    {
        if (!is_array($members)) {
            throw ScimError::invalid('members must be a list of {value}.');
        }
        $ids = [];
        foreach ($members as $member) {
            $value = is_array($member) ? ($member['value'] ?? null) : $member;
            if (!is_string($value) || $value === '') {
                throw ScimError::invalid('members must be a list of {value}.');
            }
            $ids[] = $value;
        }

        return $ids;
    }

    /**
     * @param array<string, mixed> $body
     * @throws ScimError
     */
    private static function name(array $body): string
    {
        $name = is_string($body['displayName'] ?? null) ? trim($body['displayName']) : '';
        if ($name === '' || mb_strlen($name) > 120) {
            throw ScimError::invalid('displayName must be 1 to 120 characters.');
        }

        return $name;
    }

    private static function slug(string $name): string
    {
        $slug = strtolower(trim((string) preg_replace('/[^a-z0-9]+/i', '-', $name), '-'));

        return $slug === '' ? 'group' : substr($slug, 0, 64);
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function externalId(array $body): ?string
    {
        $externalId = $body['externalId'] ?? null;

        return is_string($externalId) && trim($externalId) !== '' ? trim($externalId) : null;
    }

    private static function datetime(mixed $value): string
    {
        return $value instanceof \DateTimeImmutable ? $value->format(DATE_ATOM) : (new \DateTimeImmutable((string) $value))->format(DATE_ATOM);
    }
}

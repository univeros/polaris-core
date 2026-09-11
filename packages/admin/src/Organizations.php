<?php

declare(strict_types=1);

namespace Polaris\Admin;

use InvalidArgumentException;
use Polaris\Authorization\MembershipService;
use Polaris\Authorization\OrganizationService;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\MemberRolesChanged;
use Polaris\Exception\LastOwnerException;
use Polaris\Exception\MemberNotFoundException;
use Polaris\Model\Membership;
use Polaris\Model\MembershipRole;
use Polaris\Model\Organization;
use Polaris\Model\Role;
use Polaris\Repository\MembershipRepository;
use Polaris\Repository\MembershipRoleRepository;
use Polaris\Repository\OrganizationRepository;
use Polaris\Repository\RoleRepository;
use Polaris\Repository\RowMapper;
use Polaris\Schema\Schema as Registry;
use Psr\EventDispatcher\EventDispatcherInterface;

use function array_keys;
use function array_slice;
use function count;

use const DATE_ATOM;

/**
 * The operator's view of the organizations: a cursor-paginated list, one organization with its
 * members, a member's roles set by an instance operator (the last owner stays), soft deletion.
 */
final class Organizations
{
    public const int DEFAULT_LIMIT = 50;
    public const int MAX_LIMIT = 200;

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly OrganizationRepository $organizations,
        private readonly MembershipRepository $memberships,
        private readonly MembershipRoleRepository $membershipRoles,
        private readonly RoleRepository $roles,
        private readonly MembershipService $members,
        private readonly OrganizationService $service,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * @return array{data: list<array<string, mixed>>, next_cursor: string|null}
     */
    public function list(?string $status = null, ?string $cursor = null, int $limit = self::DEFAULT_LIMIT): array
    {
        $limit = max(1, min(self::MAX_LIMIT, $limit));
        $criteria = [];
        if ($status !== null) {
            $criteria['status'] = $status;
        }
        if ($cursor !== null) {
            $criteria['id'] = Condition::gt($cursor);
        }
        $model = Registry::for(Organization::class);
        $rows = $this->database->findMany($model->table, $criteria, ['id' => 'asc'], $limit + 1);
        $data = [];
        foreach (array_slice($rows, 0, $limit) as $row) {
            /** @var Organization $organization */
            $organization = RowMapper::hydrate($model, $row);
            $data[] = self::shape($organization);
        }

        return ['data' => $data, 'next_cursor' => count($rows) > $limit && $data !== [] ? $data[count($data) - 1]['id'] : null];
    }

    public function find(string $id): ?Organization
    {
        return $this->organizations->find($id);
    }

    /**
     * @return array<string, mixed>
     */
    public static function shape(Organization $organization): array
    {
        return [
            'id' => $organization->id,
            'name' => $organization->name,
            'slug' => $organization->slug,
            'status' => $organization->status,
            'created_by' => $organization->createdBy,
            'created_at' => $organization->createdAt->format(DATE_ATOM),
            'updated_at' => $organization->updatedAt->format(DATE_ATOM),
        ];
    }

    /**
     * @return array<string, mixed> the organization with its members (emails included, this is an operator)
     */
    public function read(Organization $organization): array
    {
        return [...self::shape($organization), 'members' => $this->members->listMembers($organization->id, true)];
    }

    public function delete(Organization $organization, string $actorId): void
    {
        $this->service->softDelete($organization, $actorId);
    }

    /**
     * Replaces a member's roles. An instance operator may grant any role of the organization; the
     * organization keeps at least one owner.
     *
     * @param list<string> $roleSlugs
     *
     * @throws MemberNotFoundException
     * @throws InvalidArgumentException an unknown slug
     * @throws LastOwnerException
     */
    public function setMemberRoles(string $organizationId, string $userId, array $roleSlugs, string $actorId): void
    {
        $membership = $this->memberships->findOneBy(['userId' => $userId, 'organizationId' => $organizationId]);
        if (!$membership instanceof Membership) {
            throw new MemberNotFoundException('The user is not a member of this organization.');
        }
        $wanted = [];
        foreach ($roleSlugs as $slug) {
            $role = $this->roles->findOneBy(['organizationId' => $organizationId, 'slug' => $slug]);
            if (!$role instanceof Role) {
                throw new InvalidArgumentException("Unknown role for this organization: $slug");
            }
            $wanted[$role->id] = true;
        }
        $owner = $this->roles->findOneBy(['organizationId' => $organizationId, 'slug' => PermissionCatalog::ROLE_OWNER]);
        $ownerId = $owner instanceof Role ? $owner->id : null;
        $current = [];
        foreach ($this->membershipRoles->findBy(['membershipId' => $membership->id]) as $link) {
            $current[$link->roleId] = $link;
        }
        if ($ownerId !== null && isset($current[$ownerId]) && !isset($wanted[$ownerId]) && $this->activeOwners($organizationId, $ownerId) <= 1) {
            throw new LastOwnerException('The organization must keep at least one owner.');
        }
        foreach ($current as $roleId => $link) {
            if (isset($wanted[$roleId])) {
                unset($wanted[$roleId]);
            } else {
                $this->unitOfWork->remove($link);
            }
        }
        foreach (array_keys($wanted) as $roleId) {
            $link = new MembershipRole();
            $link->membershipId = $membership->id;
            $link->roleId = $roleId;
            $this->unitOfWork->persist($link);
        }
        $this->unitOfWork->flush();

        $this->events->dispatch(new MemberRolesChanged($organizationId, $userId, $roleSlugs, $actorId));
    }

    private function activeOwners(string $organizationId, string $ownerRoleId): int
    {
        $count = 0;
        foreach ($this->memberships->findBy(['organizationId' => $organizationId, 'status' => Membership::STATUS_ACTIVE]) as $membership) {
            if ($this->membershipRoles->findOneBy(['membershipId' => $membership->id, 'roleId' => $ownerRoleId]) !== null) {
                ++$count;
            }
        }

        return $count;
    }
}

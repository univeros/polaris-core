<?php

declare(strict_types=1);

namespace Polaris\Tests\Persistence;

use Polaris\Repository\RoleRepository;
use Polaris\Repository\RolePermissionRepository;
use Polaris\Repository\PermissionRepository;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Polaris\Model\Membership;
use Polaris\Model\MembershipRole;
use Polaris\Model\Permission;
use Polaris\Model\Role;
use Polaris\Model\RolePermission;

/**
 * Verifies the #28 RBAC entities and migrations against a real database driver: the migrations
 * create the expected portable tables, columns, composite primary keys and unique indexes; the
 * attribute-mapped entities round-trip through them; the `ON DELETE CASCADE` foreign keys on the
 * join tables remove grants when a role/permission/membership is deleted; and the migrations roll
 * back cleanly.
 */
final class RolesPermissionsPersistenceTest extends DatabaseTestCase
{
    public function testMigrationsCreateTheTablesWithKeysAndIndexes(): void
    {
        $database = $this->adapter;

        self::assertTrue($this->hasTable('auth_roles'));
        self::assertTrue($this->hasTable('auth_permissions'));
        self::assertTrue($this->hasTable('auth_role_permissions'));
        self::assertTrue($this->hasTable('auth_membership_roles'));

        $roles = 'auth_roles';
        foreach (['id', 'organization_id', 'name', 'slug', 'description', 'is_system'] as $column) {
            self::assertTrue($this->hasColumn($roles, $column), "auth_roles.$column should exist");
        }
        self::assertSame(['id'], $this->primaryKey($roles));
        self::assertTrue($this->hasIndex($roles, ['organization_id', 'slug']));

        $permissions = 'auth_permissions';
        foreach (['id', 'key', 'description'] as $column) {
            self::assertTrue($this->hasColumn($permissions, $column), "auth_permissions.$column should exist");
        }
        self::assertSame(['id'], $this->primaryKey($permissions));
        self::assertTrue($this->hasIndex($permissions, ['key']));

        $rolePermissions = 'auth_role_permissions';
        self::assertSame(['role_id', 'permission_id'], $this->primaryKey($rolePermissions));

        $membershipRoles = 'auth_membership_roles';
        self::assertSame(['membership_id', 'role_id'], $this->primaryKey($membershipRoles));
    }

    public function testRoleRoundTrips(): void
    {
        $repository = new RoleRepository($this->adapter, $this->identities);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = Uuid::v7()->toRfc4122();
        $role->name = 'Owner';
        $role->slug = 'owner';
        $role->description = 'Full control of the organization';
        $role->isSystem = true;
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $this->unitOfWork->persist($role);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['id' => $role->id]);

        self::assertInstanceOf(Role::class, $found);
        self::assertSame($role->organizationId, $found->organizationId);
        self::assertSame('Owner', $found->name);
        self::assertSame('owner', $found->slug);
        self::assertSame('Full control of the organization', $found->description);
        self::assertTrue($found->isSystem);
    }

    public function testSystemRoleAllowsNullOrganization(): void
    {
        $repository = new RoleRepository($this->adapter, $this->identities);
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = null;
        $role->name = 'Super Admin';
        $role->slug = 'superadmin';
        $role->isSystem = true;
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $this->unitOfWork->persist($role);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['id' => $role->id]);

        self::assertInstanceOf(Role::class, $found);
        self::assertNull($found->organizationId);
        self::assertNull($found->description);
    }

    public function testPermissionRoundTrips(): void
    {
        $repository = new PermissionRepository($this->adapter, $this->identities);

        $permission = new Permission();
        $permission->id = Uuid::v7()->toRfc4122();
        $permission->key = 'test.permission';
        $permission->description = 'A custom, non-catalog permission';
        $this->unitOfWork->persist($permission);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        $found = $repository->findOneBy(['key' => 'test.permission']);

        self::assertInstanceOf(Permission::class, $found);
        self::assertSame('test.permission', $found->key);
        self::assertSame('A custom, non-catalog permission', $found->description);
    }

    public function testRolePermissionGrantRoundTrips(): void
    {
        [$roleId, $permissionId] = $this->seedRoleAndPermission();

        $grants = new RolePermissionRepository($this->adapter, $this->identities);
        $grant = new RolePermission();
        $grant->roleId = $roleId;
        $grant->permissionId = $permissionId;
        $this->unitOfWork->persist($grant);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        $found = $grants->findOneBy(['roleId' => $roleId, 'permissionId' => $permissionId]);

        self::assertInstanceOf(RolePermission::class, $found);
        self::assertSame($roleId, $found->roleId);
        self::assertSame($permissionId, $found->permissionId);
    }

    public function testDeletingARoleCascadesItsPermissionGrants(): void
    {
        [$roleId, $permissionId] = $this->seedRoleAndPermission();
        $this->insertRolePermission($roleId, $permissionId);

        $database = $this->adapter;
        self::assertSame(1, $database->count('auth_role_permissions', ['role_id' => $roleId]));

        $database->delete('auth_roles', ['id' => $roleId]);

        self::assertSame(0, $database->count('auth_role_permissions', ['role_id' => $roleId]));
        self::assertSame(1, $database->count('auth_permissions', ['id' => $permissionId]), 'The permission itself must remain.');
    }

    public function testDeletingAPermissionCascadesItsRoleGrants(): void
    {
        [$roleId, $permissionId] = $this->seedRoleAndPermission();
        $this->insertRolePermission($roleId, $permissionId);

        $database = $this->adapter;
        self::assertSame(1, $database->count('auth_role_permissions', ['permission_id' => $permissionId]));

        $database->delete('auth_permissions', ['id' => $permissionId]);

        self::assertSame(0, $database->count('auth_role_permissions', ['permission_id' => $permissionId]));
        self::assertSame(1, $database->count('auth_roles', ['id' => $roleId]), 'The role itself must remain.');
    }

    public function testDeletingAMembershipCascadesItsRoleGrants(): void
    {
        [$roleId] = $this->seedRoleAndPermission();
        $membershipId = $this->seedMembership();
        $this->insertMembershipRole($membershipId, $roleId);

        $database = $this->adapter;
        self::assertSame(1, $database->count('auth_membership_roles', ['membership_id' => $membershipId]));

        $database->delete('auth_memberships', ['id' => $membershipId]);

        self::assertSame(0, $database->count('auth_membership_roles', ['membership_id' => $membershipId]));
        self::assertSame(1, $database->count('auth_roles', ['id' => $roleId]), 'The role itself must remain.');
    }

    public function testDeletingARoleCascadesItsMembershipGrants(): void
    {
        [$roleId] = $this->seedRoleAndPermission();
        $membershipId = $this->seedMembership();
        $this->insertMembershipRole($membershipId, $roleId);

        $database = $this->adapter;
        self::assertSame(1, $database->count('auth_membership_roles', ['role_id' => $roleId]));

        $database->delete('auth_roles', ['id' => $roleId]);

        self::assertSame(0, $database->count('auth_membership_roles', ['role_id' => $roleId]));
        self::assertSame(1, $database->count('auth_memberships', ['id' => $membershipId]), 'The membership itself must remain.');
    }

    /**
     * Persists a role and a permission and returns their ids `[roleId, permissionId]`, so join-table
     * inserts have parents to satisfy the foreign keys.
     *
     * @return array{0: string, 1: string}
     */
    private function seedRoleAndPermission(): array
    {
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = Uuid::v7()->toRfc4122();
        $role->name = 'Admin';
        $role->slug = 'admin';
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $this->unitOfWork->persist($role);
        $this->unitOfWork->flush();

        $permission = new Permission();
        $permission->id = Uuid::v7()->toRfc4122();
        $permission->key = 'test.grant';
        $permission->description = 'A custom, non-catalog permission';
        $this->unitOfWork->persist($permission);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        return [$role->id, $permission->id];
    }

    private function seedMembership(): string
    {
        $now = new DateTimeImmutable('2026-06-09 10:00:00');

        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = Uuid::v7()->toRfc4122();
        $membership->organizationId = Uuid::v7()->toRfc4122();
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        $this->unitOfWork->persist($membership);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        return $membership->id;
    }

    private function insertRolePermission(string $roleId, string $permissionId): void
    {
        $grant = new RolePermission();
        $grant->roleId = $roleId;
        $grant->permissionId = $permissionId;
        $this->unitOfWork->persist($grant);
        $this->unitOfWork->flush();
        $this->unitOfWork->clear();
    }

    private function insertMembershipRole(string $membershipId, string $roleId): void
    {
        $grant = new MembershipRole();
        $grant->membershipId = $membershipId;
        $grant->roleId = $roleId;
        $this->unitOfWork->persist($grant);
        $this->unitOfWork->flush();
        $this->unitOfWork->clear();
    }
}

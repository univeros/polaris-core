<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Persistence;

use Polaris\Contract\TokenInterface;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use Polaris\Authorization\Gate;
use Polaris\Authorization\PermissionResolver;
use Polaris\Model\Membership;
use Polaris\Model\MembershipRole;
use Polaris\Model\Role;
use Polaris\Model\RolePermission;
use Polaris\Exception\AuthorizationException;
use Polaris\Repository\MembershipRepository;
use Polaris\Repository\MembershipRoleRepository;
use Polaris\Repository\OrganizationRepository;
use Polaris\Repository\PermissionRepository;
use Polaris\Repository\RolePermissionRepository;
use Polaris\Repository\RoleRepository;
use Polaris\Repository\UserRepository;

use function is_string;

/**
 * Verifies the #36 {@see Gate} against a real driver: a programmatic `authorize()` passes for a
 * permission the caller holds in their active org and throws {@see AuthorizationException} for one
 * they do not.
 */
final class GateTest extends DatabaseTestCase
{
    private const string ORG = '01910000-0000-7000-8000-0000000000bb';

    public function testAuthorizePassesForAHeldPermission(): void
    {
        $token = $this->memberWith('members.read');

        $this->gate()->authorize($token, 'members.read');

        $this->expectNotToPerformAssertions();
    }

    public function testAuthorizeThrowsForAMissingPermission(): void
    {
        $token = $this->memberWith('members.read');

        self::assertFalse($this->gate()->allows($token, 'members.invite'));

        $this->expectException(AuthorizationException::class);
        $this->gate()->authorize($token, 'members.invite');
    }

    private function gate(): Gate
    {
        return new Gate(new PermissionResolver(
            new UserRepository($this->adapter, $this->identities),
            new OrganizationRepository($this->adapter, $this->identities),
            new MembershipRepository($this->adapter, $this->identities),
            new MembershipRoleRepository($this->adapter, $this->identities),
            new RoleRepository($this->adapter, $this->identities),
            new RolePermissionRepository($this->adapter, $this->identities),
            new PermissionRepository($this->adapter, $this->identities),
        ));
    }

    /**
     * Creates a member of {@see self::ORG} holding exactly the given permission via a single role,
     * and returns a token scoped to that org.
     */
    private function memberWith(string $permissionKey): TokenInterface
    {
        $now = new DateTimeImmutable('2026-06-10 10:00:00');
        $userId = Uuid::v7()->toRfc4122();

        $membership = new Membership();
        $membership->id = Uuid::v7()->toRfc4122();
        $membership->userId = $userId;
        $membership->organizationId = self::ORG;
        $membership->status = Membership::STATUS_ACTIVE;
        $membership->createdAt = $now;
        $membership->updatedAt = $now;
        $this->unitOfWork->persist($membership);
        $this->unitOfWork->flush();

        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->organizationId = self::ORG;
        $role->name = 'limited';
        $role->slug = 'limited';
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $this->unitOfWork->persist($role);
        $this->unitOfWork->flush();

        $grant = new RolePermission();
        $grant->roleId = $role->id;
        $grant->permissionId = $this->permissionId($permissionKey);
        $this->unitOfWork->persist($grant);
        $this->unitOfWork->flush();

        $link = new MembershipRole();
        $link->membershipId = $membership->id;
        $link->roleId = $role->id;
        $this->unitOfWork->persist($link);
        $this->unitOfWork->flush();

        $this->unitOfWork->clear();

        return new class ($userId, self::ORG) implements TokenInterface {
            public function __construct(private readonly string $sub, private readonly string $org)
            {
            }

            public function getToken(): string
            {
                return '';
            }

            public function getMetadata(?string $key = null): mixed
            {
                return match ($key) {
                    'sub' => $this->sub,
                    'org' => $this->org,
                    default => null,
                };
            }
        };
    }

    private function permissionId(string $key): string
    {
        foreach ($this->adapter->findMany('auth_permissions', ['key' => $key]) as $row) {
            if (is_string($row['id'] ?? null)) {
                return $row['id'];
            }
        }

        self::fail("Permission $key was not seeded.");
    }
}

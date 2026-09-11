<?php

declare(strict_types=1);

namespace Polaris\Admin;

use DateTimeImmutable;
use Polaris\Admin\Model\AdminGrant;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Repository\GenericRepository;
use Polaris\Repository\IdentityMap;
use Polaris\Schema\Schema as Registry;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The operator roles of Polaris users (`polaris_admin_grant`): one grant per user, on the instance
 * or on one organization, optionally expiring. A superadmin needs no grant: they are an owner.
 */
final class Grants
{
    /** @var GenericRepository<AdminGrant> */
    private readonly GenericRepository $grants;

    public function __construct(
        DatabaseAdapter $database,
        IdentityMap $identities,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly ClockInterface $clock,
    ) {
        $this->grants = new GenericRepository($database, Registry::for(AdminGrant::class), $identities);
    }

    /**
     * Grants the role, replacing the user's previous grant when there is one.
     */
    public function grant(string $userId, Role $role, string $scope = Principal::SCOPE_INSTANCE, ?DateTimeImmutable $expiresAt = null, ?string $grantedBy = null): AdminGrant
    {
        $grant = $this->grants->findOneBy(['userId' => $userId]) ?? new AdminGrant();
        if ($grant->id === '') {
            $grant->id = Uuid::v7()->toRfc4122();
            $grant->userId = $userId;
            $grant->createdAt = $this->clock->now();
        }
        $grant->role = $role->value;
        $grant->scope = $scope;
        $grant->expiresAt = $expiresAt;
        $grant->grantedBy = $grantedBy;
        $this->unitOfWork->persist($grant);
        $this->unitOfWork->flush();

        return $grant;
    }

    /**
     * The user's grant when it has not expired.
     */
    public function forUser(string $userId): ?AdminGrant
    {
        $grant = $this->grants->findOneBy(['userId' => $userId]);
        if ($grant === null || ($grant->expiresAt !== null && $grant->expiresAt <= $this->clock->now())) {
            return null;
        }

        return $grant;
    }

    public function find(string $id): ?AdminGrant
    {
        return $this->grants->find($id);
    }

    /**
     * @return list<AdminGrant>
     */
    public function all(): array
    {
        return [...$this->grants->findAll()];
    }

    public function revoke(string $id): bool
    {
        $grant = $this->grants->find($id);
        if ($grant === null) {
            return false;
        }
        $this->unitOfWork->remove($grant);
        $this->unitOfWork->flush();

        return true;
    }
}

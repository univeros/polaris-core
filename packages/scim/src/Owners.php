<?php

declare(strict_types=1);

namespace Polaris\Scim;

use Polaris\Authorization\PermissionCatalog;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\Membership;
use Polaris\Scim\Model\Connection;

/**
 * The organization's last-active-owner guarantee for the directory's writes (core's
 * `MembershipService` needs an acting user; a directory has none): a write that would leave an
 * organization with an active owner without one is rolled back and refused.
 */
final class Owners
{
    public function __construct(private readonly DatabaseAdapter $database)
    {
    }

    /**
     * Runs `$write` in one transaction, refused (409) when the organization loses its last active owner.
     *
     * @template T
     * @param callable(): T $write
     * @return T
     * @throws ScimError
     */
    public function keep(Connection $connection, callable $write): mixed
    {
        return $this->database->transaction(function () use ($connection, $write): mixed {
            $before = $this->active($connection->organizationId);
            $result = $write();
            if ($before > 0 && $this->active($connection->organizationId) === 0) {
                throw new ScimError(409, 'The organization must keep at least one active owner.');
            }

            return $result;
        });
    }

    private function active(string $organizationId): int
    {
        $role = $this->database->findOne('auth_roles', ['organization_id' => $organizationId, 'slug' => PermissionCatalog::ROLE_OWNER]);
        $count = 0;
        foreach ($role === null ? [] : $this->database->findMany('auth_membership_roles', ['role_id' => $role['id']]) as $link) {
            $membership = $this->database->findOne('auth_memberships', ['id' => $link['membership_id'], 'organization_id' => $organizationId]);
            if (($membership['status'] ?? null) === Membership::STATUS_ACTIVE) {
                $count++;
            }
        }

        return $count;
    }
}

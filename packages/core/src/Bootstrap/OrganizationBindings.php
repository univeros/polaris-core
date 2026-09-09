<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Polaris\Contract\UnitOfWorkInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Polaris\Authorization\EscalationGuard;
use Polaris\Authorization\InvitationService;
use Polaris\Authorization\MembershipService;
use Polaris\Authorization\OrganizationService;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionResolver;
use Polaris\Authorization\RoleService;
use Polaris\Http\Auth\AcceptInviteEndpoint;
use Polaris\Http\Orgs\ChangeMemberRolesEndpoint;
use Polaris\Http\Orgs\ChangeMemberStatusEndpoint;
use Polaris\Http\Orgs\CreateInviteEndpoint;
use Polaris\Http\Orgs\CreateOrganizationEndpoint;
use Polaris\Http\Orgs\CreateRoleEndpoint;
use Polaris\Http\Orgs\DeleteOrganizationEndpoint;
use Polaris\Http\Orgs\DeleteRoleEndpoint;
use Polaris\Http\Orgs\ListInvitesEndpoint;
use Polaris\Http\Orgs\ListMembersEndpoint;
use Polaris\Http\Orgs\ListOrganizationsEndpoint;
use Polaris\Http\Orgs\ListPermissionsEndpoint;
use Polaris\Http\Orgs\ListRolesEndpoint;
use Polaris\Http\Orgs\ReadOrganizationEndpoint;
use Polaris\Http\Orgs\RemoveMemberEndpoint;
use Polaris\Http\Orgs\RevokeInviteEndpoint;
use Polaris\Http\Orgs\UpdateOrganizationEndpoint;
use Polaris\Http\Orgs\UpdateRoleEndpoint;
use Polaris\Http\Users\DeleteUserEndpoint;
use Polaris\Http\Users\DisableUserEndpoint;
use Polaris\Http\Users\EnableUserEndpoint;
use Polaris\Http\Users\ReadUserEndpoint;
use Polaris\Http\Users\UpdateUserEndpoint;
use Polaris\Identity\SessionService;
use Polaris\Identity\UserAdminService;
use Polaris\Repository\EmailVerificationRepository;
use Polaris\Repository\InvitationRepository;
use Polaris\Repository\MembershipRepository;
use Polaris\Repository\MembershipRoleRepository;
use Polaris\Repository\MfaFactorRepository;
use Polaris\Repository\OrganizationRepository;
use Polaris\Repository\OtpChallengeRepository;
use Polaris\Repository\PasswordResetRepository;
use Polaris\Repository\PermissionRepository;
use Polaris\Repository\RolePermissionRepository;
use Polaris\Repository\RoleRepository;
use Polaris\Repository\UserRepository;
use Polaris\Security\Pepper;

/**
 * Wires organization management: the org/membership/invitation/role services, user
 * administration, and the `/orgs`, `/permissions`, and `/users` domains.
 */
final class OrganizationBindings
{
    public function apply(Container $container): void
    {
        $this->bindOrganizations($container);
    }

    /**
     * Bind the organization service — a transactional create that clones the owner/admin/member
     * system role templates into org-scoped roles and grants the creator an active `owner`
     * membership — plus the `/orgs` domains. The repositories are autowired; the
     * {@see PermissionCatalog} is bound with no host contributors by default (a host may rebind it).
     */
    private function bindOrganizations(Container $container): void
    {
        $container->singleton(PermissionCatalog::class, static fn(): PermissionCatalog => new PermissionCatalog());

        $container->singleton(
            OrganizationService::class,
            static fn(
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                PermissionRepository $permissions,
                PermissionCatalog $catalog,
                SessionService $sessions,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): OrganizationService => new OrganizationService(
                $organizations,
                $memberships,
                $permissions,
                $catalog,
                $sessions,
                $unitOfWork,
                $clock,
                $events,
            ),
        );

        $container->singleton(CreateOrganizationEndpoint::class);
        $container->singleton(ListOrganizationsEndpoint::class);
        $container->singleton(
            ReadOrganizationEndpoint::class,
            static fn(OrganizationRepository $organizations): ReadOrganizationEndpoint
                => new ReadOrganizationEndpoint($organizations),
        );
        $container->singleton(UpdateOrganizationEndpoint::class);
        $container->singleton(DeleteOrganizationEndpoint::class);

        $container->singleton(
            EscalationGuard::class,
            static fn(
                RolePermissionRepository $rolePermissions,
                PermissionRepository $permissions,
            ): EscalationGuard => new EscalationGuard($rolePermissions, $permissions),
        );

        $container->singleton(
            MembershipService::class,
            static fn(
                MembershipRepository $memberships,
                MembershipRoleRepository $membershipRoles,
                RoleRepository $roles,
                UserRepository $users,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                SessionService $sessions,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): MembershipService => new MembershipService(
                $memberships,
                $membershipRoles,
                $roles,
                $users,
                $resolver,
                $escalation,
                $unitOfWork,
                $sessions,
                $clock,
                $events,
            ),
        );
        $container->singleton(ListMembersEndpoint::class);
        $container->singleton(ChangeMemberRolesEndpoint::class);
        $container->singleton(ChangeMemberStatusEndpoint::class);
        $container->singleton(RemoveMemberEndpoint::class);

        $container->singleton(
            InvitationService::class,
            static fn(
                InvitationRepository $invitations,
                OrganizationRepository $organizations,
                MembershipRepository $memberships,
                MembershipRoleRepository $membershipRoles,
                RoleRepository $roles,
                UserRepository $users,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): InvitationService => new InvitationService(
                $invitations,
                $organizations,
                $memberships,
                $membershipRoles,
                $roles,
                $users,
                $resolver,
                $escalation,
                $unitOfWork,
                $pepper,
                $clock,
                $events,
            ),
        );
        $container->singleton(CreateInviteEndpoint::class);
        $container->singleton(ListInvitesEndpoint::class);
        $container->singleton(RevokeInviteEndpoint::class);
        $container->singleton(AcceptInviteEndpoint::class);

        $container->singleton(
            RoleService::class,
            static fn(
                RoleRepository $roles,
                RolePermissionRepository $rolePermissions,
                PermissionRepository $permissions,
                PermissionResolver $resolver,
                EscalationGuard $escalation,
                UnitOfWorkInterface $unitOfWork,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): RoleService => new RoleService(
                $roles,
                $rolePermissions,
                $permissions,
                $resolver,
                $escalation,
                $unitOfWork,
                $clock,
                $events,
            ),
        );
        $container->singleton(ListRolesEndpoint::class);
        $container->singleton(CreateRoleEndpoint::class);
        $container->singleton(UpdateRoleEndpoint::class);
        $container->singleton(DeleteRoleEndpoint::class);
        $container->singleton(ListPermissionsEndpoint::class);

        $container->singleton(
            UserAdminService::class,
            static fn(
                UserRepository $users,
                MfaFactorRepository $mfaFactors,
                OtpChallengeRepository $otpChallenges,
                EmailVerificationRepository $emailVerifications,
                PasswordResetRepository $passwordResets,
                PermissionResolver $resolver,
                SessionService $sessions,
                UnitOfWorkInterface $unitOfWork,
                Pepper $pepper,
                ClockInterface $clock,
                EventDispatcherInterface $events,
            ): UserAdminService => new UserAdminService(
                $users,
                $mfaFactors,
                $otpChallenges,
                $emailVerifications,
                $passwordResets,
                $resolver,
                $sessions,
                $unitOfWork,
                $pepper,
                $clock,
                $events,
            ),
        );
        $container->singleton(ReadUserEndpoint::class);
        $container->singleton(UpdateUserEndpoint::class);
        $container->singleton(DisableUserEndpoint::class);
        $container->singleton(EnableUserEndpoint::class);
        $container->singleton(DeleteUserEndpoint::class);
    }
}

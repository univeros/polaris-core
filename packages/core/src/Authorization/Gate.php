<?php

declare(strict_types=1);

namespace Polaris\Authorization;

use Polaris\Contract\TokenInterface;
use Polaris\Exception\AuthorizationException;

use function array_fill_keys;
use function array_filter;
use function array_values;
use function is_array;
use function is_string;

/**
 * The programmatic authorization check (`docs/auth/rbac.md` §5b): given an authenticated token,
 * does the caller hold the required permission(s) in their active org?
 *
 * It resolves the caller's effective permissions for the token's `org` via {@see PermissionResolver}
 * (so the system `superadmin` override applies automatically) and tests the requirement against
 * them. The `AuthorizationMiddleware` uses {@see allows()} for
 * the declarative edge check; domain services use {@see authorize()} for row-level / conditional
 * checks. Policy callbacks for rules permissions alone cannot express (e.g. last-owner protection)
 * are attached by the domains that own those invariants.
 */
final readonly class Gate
{
    /** The token metadata naming the permissions a delegate's owner handed it (set by a bearer resolver). */
    public const string DELEGATED = 'delegated';

    public function __construct(private PermissionResolver $permissions)
    {
    }

    /**
     * @throws AuthorizationException when the caller lacks any of the required permissions
     */
    public function authorize(TokenInterface $token, string ...$permissions): void
    {
        if (!$this->allows($token, ...$permissions)) {
            throw new AuthorizationException('You do not have permission to perform this action.');
        }
    }

    public function allows(TokenInterface $token, string ...$permissions): bool
    {
        return $this->allowsAuthority($this->authority($token), ...$permissions);
    }

    /**
     * The caller's database-resolved authority for their active org. The middleware attaches it
     * to the request so downstream guards never have to trust token claims for role decisions.
     *
     * A token a plugin's bearer resolver built for a delegate (an API key, an OAuth client, an agent)
     * carries {@see self::DELEGATED}, the permissions the owner delegated: the authority's scope is the
     * intersection, the roles stay the owner's without the `superadmin` override. Core's own access tokens never carry it, and a resolver
     * sets it in-process, so a claim on the wire cannot widen anything.
     */
    public function authority(TokenInterface $token): ResolvedAuthority
    {
        $organization = $token->getMetadata('org');
        $authority = $this->permissions->resolve(
            (string) $token->getMetadata('sub'),
            is_string($organization) ? $organization : null,
        );
        $delegated = $token->getMetadata(self::DELEGATED);
        if (!is_array($delegated)) {
            return $authority;
        }
        $allowed = array_fill_keys(array_filter($delegated, is_string(...)), true);

        // The global override is the owner's, not the delegate's: a superadmin's key or token acts within
        // its list only, and the cross-organization and escalation exemptions do not follow it.
        $roles = array_values(array_filter($authority->roles, static fn(string $role): bool => $role !== PermissionCatalog::ROLE_SUPERADMIN));

        return new ResolvedAuthority($roles, array_values(array_filter($authority->scope, static fn(string $permission): bool => isset($allowed[$permission]))));
    }

    public function allowsAuthority(ResolvedAuthority $authority, string ...$permissions): bool
    {
        $granted = array_fill_keys($authority->scope, true);
        foreach ($permissions as $permission) {
            if (!isset($granted[$permission])) {
                return false;
            }
        }

        return true;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Admin\Principal;

use Polaris\Admin\Grants;
use Polaris\Admin\Impersonation;
use Polaris\Admin\Keys;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionResolver;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use SensitiveParameter;

use function in_array;
use function is_string;
use function str_starts_with;

/**
 * Resolves the bearer of an admin route: `pak_...` is an API key (hash, expiry, allowlist); anything
 * else is a Polaris access token whose user holds a grant or the superadmin role. An impersonation
 * token resolves to nobody, marked, so the route answers `admin/impersonation_denied`.
 */
final class Principals
{
    public const string ATTRIBUTE = 'polaris.admin.principal';
    public const string IMPERSONATED = 'polaris.admin.impersonated';

    public function __construct(
        private readonly Grants $grants,
        private readonly Keys $keys,
        private readonly TokenFactoryInterface $tokens,
        private readonly UserRepository $users,
        private readonly PermissionResolver $resolver,
    ) {
    }

    public function resolve(#[SensitiveParameter] ?string $bearer, ?string $ip): Resolution
    {
        if ($bearer === null || $bearer === '') {
            return new Resolution();
        }
        if (str_starts_with($bearer, Keys::PREFIX)) {
            $key = $this->keys->authenticate($bearer, $ip);

            return new Resolution($key === null ? null : new Principal($key->id, Principal::TYPE_API_KEY, Role::from($key->role), $key->scope));
        }
        try {
            $token = $this->tokens->fromTokenString($bearer);
        } catch (AuthorizationTokenException) {
            return new Resolution();
        }
        if ($token->getMetadata(Impersonation::CLAIM) !== null) {
            return new Resolution(impersonated: true);
        }
        $userId = $token->getMetadata('sub');
        if (!is_string($userId) || $userId === '') {
            return new Resolution();
        }
        $user = $this->users->find($userId);
        if (!$user instanceof User || $user->status === User::STATUS_DISABLED) {
            return new Resolution();
        }
        $grant = $this->grants->forUser($userId);
        if ($grant !== null) {
            return new Resolution(new Principal($userId, Principal::TYPE_USER, Role::from($grant->role), $grant->scope));
        }
        if (in_array(PermissionCatalog::ROLE_SUPERADMIN, $this->resolver->resolve($userId, null)->roles, true)) {
            return new Resolution(new Principal($userId, Principal::TYPE_USER, Role::Owner));
        }

        return new Resolution();
    }
}

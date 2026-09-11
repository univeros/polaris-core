<?php

declare(strict_types=1);

namespace Polaris\Admin;

use LogicException;
use Polaris\Admin\Principal\Principal;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Config\AuthConfig;
use Polaris\Exception\AuthorizationException;
use Polaris\Exception\UserNotFoundException;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\SessionPrincipalResolverInterface;
use Polaris\Token\TokenService;
use Psr\Clock\ClockInterface;

use function in_array;

/**
 * An access token that acts as the user for one access-token lifetime: no session behind it, so it
 * cannot be refreshed, stepped up or switched; `amr: ["impersonation"]`, `mfa: false`, and the
 * `impersonated_by` claim, which the admin routes refuse.
 */
final class Impersonation
{
    public const string CLAIM = 'impersonated_by';
    public const string CLAIM_TYPE = 'impersonator_type';
    public const string AMR = 'impersonation';

    public function __construct(
        private readonly TokenService $tokens,
        private readonly SessionPrincipalResolverInterface $principals,
        private readonly UserRepository $users,
        private readonly AuthConfig $auth,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @return array{access_token: string, token_type: string, expires_in: int, impersonated_by: string}
     *
     * @throws UserNotFoundException
     * @throws LogicException          the account is not active
     * @throws AuthorizationException  the user is a superadmin
     */
    public function start(string $userId, Principal $by): array
    {
        $user = $this->users->find($userId);
        if (!$user instanceof User) {
            throw new UserNotFoundException('The user does not exist.');
        }
        if ($user->status !== User::STATUS_ACTIVE) {
            throw new LogicException('The account is not active.');
        }
        $base = $this->principals->resolve($userId, null);
        if (in_array(PermissionCatalog::ROLE_SUPERADMIN, $base->roles, true)) {
            throw new AuthorizationException('A superadmin cannot be impersonated.');
        }
        $principal = new SessionPrincipal(
            userId: $userId,
            organizationId: null,
            roles: $base->roles,
            scope: $base->scope,
            emailVerified: $base->emailVerified,
            mfa: false,
            amr: [self::AMR],
            authTime: $this->clock->now()->getTimestamp(),
        );

        return [
            'access_token' => $this->tokens->mint($principal, null, [self::CLAIM => $by->id, self::CLAIM_TYPE => $by->type]),
            'token_type' => 'Bearer',
            'expires_in' => $this->auth->accessToken->ttl,
            'impersonated_by' => $by->id,
        ];
    }
}

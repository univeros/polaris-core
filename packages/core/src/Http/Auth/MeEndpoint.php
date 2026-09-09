<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Contract\RepositoryInterface;
use Override;
use Polaris\Model\User;

/**
 * `GET /auth/me` — the authenticated user's identity. Organizations and roles are returned
 * as empty collections until the multi-tenant RBAC phase populates them.
 */
final class MeEndpoint extends Endpoint
{
    /**
     * @param RepositoryInterface<User> $users
     */
    public function __construct(private readonly RepositoryInterface $users)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        $user = $userId === '' ? null : $this->users->find($userId);
        if (!$user instanceof User) {
            return $this->unauthorized();
        }

        return $this->respond(200, [
            'data' => [
                'id' => $user->id,
                'email' => $user->email,
                'email_verified' => $user->emailVerifiedAt !== null,
                'display_name' => $user->displayName,
                'status' => $user->status,
                'mfa_enforced' => $user->mfaEnforced,
                'orgs' => [],
                'roles' => [],
            ],
        ]);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Http\Users;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Exception\AuthorizationException;
use Polaris\Exception\UserNotFoundException;
use Polaris\Identity\UserAdminService;

/**
 * `DELETE /users/{id}` — delete (anonymize) an account: yourself, or any user when holding
 * `users.manage`. Step-up-gated. The row survives as a tombstone (hashed email, nulled profile,
 * revoked sessions) for referential/audit integrity — the right-to-erasure flow of
 * `docs/auth/security.md` §9.
 */
final class DeleteUserEndpoint extends Endpoint
{
    public function __construct(private readonly UserAdminService $users)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        try {
            $this->users->erase($this->actorId($token), $this->actorOrg($token), (string) $input->get('id'));
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (UserNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        }

        return $this->respond(200, ['data' => ['deleted' => true]]);
    }
}

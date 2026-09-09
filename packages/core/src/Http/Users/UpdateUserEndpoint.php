<?php

declare(strict_types=1);

namespace Polaris\Http\Users;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use InvalidArgumentException;
use Override;
use Polaris\Exception\AuthorizationException;
use Polaris\Exception\UserNotFoundException;
use Polaris\Identity\UserAdminService;

use function is_string;

/**
 * `PATCH /users/{id}` — update a user's profile (display name): yourself, or any user when holding
 * `users.manage` (admin scope). Self-or-permission is enforced by the service.
 */
final class UpdateUserEndpoint extends Endpoint
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

        $displayName = $input->get('display_name');
        if ($displayName !== null && !is_string($displayName)) {
            return $this->unprocessable(['display_name must be a string.']);
        }

        try {
            $user = $this->users->updateProfile(
                $this->actorId($token),
                $this->actorOrg($token),
                (string) $input->get('id'),
                $displayName,
            );
        } catch (AuthorizationException $exception) {
            return $this->forbidden($exception->getMessage());
        } catch (UserNotFoundException $exception) {
            return $this->notFound($exception->getMessage());
        } catch (InvalidArgumentException $exception) {
            return $this->unprocessable([$exception->getMessage()]);
        }

        return $this->respond(200, ['data' => $user]);
    }
}

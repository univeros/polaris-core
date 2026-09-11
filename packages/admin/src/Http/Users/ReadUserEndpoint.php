<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Users;

use Override;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Users;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /admin/users/{id}`: one user with their activity.
 */
final class ReadUserEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Users $users)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $user = $this->users->find((string) $input->get('id'));

        return $user === null ? $this->missing('The user does not exist.') : $this->respond(200, ['data' => $this->users->shape($user)]);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Users;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Users;
use Polaris\Exception\UserNotFoundException;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function is_string;

/**
 * `POST /admin/users/{id}/password`: sets a password under the policy and ends every session.
 */
final class SetPasswordEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Users $users, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Manage);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $password = $input->get('password');
        if (!is_string($password) || $password === '') {
            return $this->invalid('password is required.');
        }
        $userId = (string) $input->get('id');
        try {
            $violations = $this->users->setPassword($userId, $password);
        } catch (UserNotFoundException $exception) {
            return $this->missing($exception->getMessage());
        }
        if ($violations !== []) {
            return $this->invalid('The password does not meet the policy.', $violations);
        }
        $this->audit->record(AdminAudit::PASSWORD_SET, $principal, $userId, client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'password_set']]);
    }
}

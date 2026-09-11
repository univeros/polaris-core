<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Users;

use LogicException;
use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Users;
use Polaris\Exception\UserNotFoundException;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /admin/users/{id}/ban`: disables the account and ends every session.
 */
final class BanUserEndpoint extends AdminEndpoint
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
        $userId = (string) $input->get('id');
        try {
            $this->users->ban($principal->id, $userId);
        } catch (LogicException $exception) {
            return $this->conflict($exception->getMessage());
        } catch (UserNotFoundException $exception) {
            return $this->missing($exception->getMessage());
        }
        $this->audit->record(AdminAudit::USER_BANNED, $principal, $userId, client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'disabled']]);
    }
}

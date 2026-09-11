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
 * `GET /admin/users`: every user, oldest first, filtered by exact `email` and `status`, paginated by `cursor`.
 */
final class ListUsersEndpoint extends AdminEndpoint
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
        $status = self::text($input->get('status'));
        if ($status !== null && !Users::isStatus($status)) {
            return $this->invalid('status must be active, disabled or locked.');
        }
        $limit = self::positiveInt($input->get('limit'), Users::DEFAULT_LIMIT);
        if ($limit === false) {
            return $this->invalid('limit must be a positive integer.');
        }

        return $this->respond(200, $this->users->list(self::text($input->get('email')), $status, self::text($input->get('cursor')), $limit));
    }
}

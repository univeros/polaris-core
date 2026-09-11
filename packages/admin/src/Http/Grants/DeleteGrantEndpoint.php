<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Grants;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Grants;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `DELETE /admin/grants/{id}`: the user is an operator no more.
 */
final class DeleteGrantEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Grants $grants, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Own);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $id = (string) $input->get('id');
        $grant = $this->grants->find($id);
        if ($grant === null || !$this->grants->revoke($id)) {
            return $this->missing('The grant does not exist.');
        }
        $this->audit->record(AdminAudit::GRANT_DELETED, $principal, $grant->userId, $grant->scope === Principal::SCOPE_INSTANCE ? null : $grant->scope, ['grant_id' => $id], $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}

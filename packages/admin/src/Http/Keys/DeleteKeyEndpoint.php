<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Keys;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Keys;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `DELETE /admin/keys/{id}`: the key stops working at once.
 */
final class DeleteKeyEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Keys $keys, private readonly AdminAudit $audit)
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
        if (!$this->keys->delete($id)) {
            return $this->missing('The key does not exist.');
        }
        $this->audit->record(AdminAudit::KEY_DELETED, $principal, $id, client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}

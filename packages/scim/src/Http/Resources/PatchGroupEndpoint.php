<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\AuditNames;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Patch;
use Polaris\Scim\ScimError;

/**
 * `PATCH /scim/v2/{connectionId}/Groups/{id}`: `displayName`, `externalId`, `members` added, removed or replaced.
 */
final class PatchGroupEndpoint extends GroupEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        try {
            $role = $this->groups->patch($connection, $this->groups->find($connection, (string) $input->get('id')), Patch::operations($this->body($input)));
        } catch (ScimError $error) {
            return $this->error($error, $connection, $input);
        }
        $this->audit->record(AuditNames::GROUP_UPDATED, $connection, (string) $role['id'], ['name' => (string) $role['name']], $this->client($input));

        return $this->scim(200, $this->groups->resource($connection, $role, $this->location($connection)));
    }
}

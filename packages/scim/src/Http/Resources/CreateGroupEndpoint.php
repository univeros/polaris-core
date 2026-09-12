<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\AuditNames;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\ScimError;

/**
 * `POST /scim/v2/{connectionId}/Groups`: a custom role with its members.
 */
final class CreateGroupEndpoint extends GroupEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        try {
            $role = $this->groups->create($connection, $this->body($input));
        } catch (ScimError $error) {
            return $this->error($error, $connection, $input);
        }
        $this->audit->record(AuditNames::GROUP_CREATED, $connection, (string) $role['id'], ['name' => (string) $role['name']], $this->client($input));

        return $this->scim(201, $this->groups->resource($connection, $role, $this->location($connection)));
    }
}

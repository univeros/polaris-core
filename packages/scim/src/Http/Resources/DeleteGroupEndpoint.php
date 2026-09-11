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
 * `DELETE /scim/v2/{connectionId}/Groups/{id}`: a custom role; 204.
 */
final class DeleteGroupEndpoint extends GroupEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        try {
            $role = $this->groups->find($connection, (string) $input->get('id'));
            $this->groups->delete($connection, $role);
        } catch (ScimError $error) {
            return $this->error($error, $connection, $input);
        }
        $this->audit->record(AuditNames::GROUP_DELETED, $connection, (string) $role['id'], ['name' => (string) $role['name']], $this->client($input));

        return new Result(204, [], ['Content-Type' => self::CONTENT_TYPE]);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\ScimError;

/**
 * `GET /scim/v2/{connectionId}/Groups/{id}`.
 */
final class ReadGroupEndpoint extends GroupEndpoint
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
        } catch (ScimError $error) {
            return $this->error($error);
        }

        return $this->scim(200, $this->groups->resource($connection, $role, $this->location($connection)));
    }
}

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
 * `POST /scim/v2/{connectionId}/Users`: a member, created or joined.
 */
final class CreateUserEndpoint extends UserEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        try {
            $user = $this->users->create($connection, $this->body($input));
        } catch (ScimError $error) {
            return $this->error($error, $connection, $input);
        }
        $this->audit->record(AuditNames::USER_CREATED, $connection, $user->id, [], $this->client($input));

        return $this->scim(201, $this->users->resource($connection, $user, $this->location($connection)));
    }
}

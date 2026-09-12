<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Model\User;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Patch;
use Polaris\Scim\ScimError;

/**
 * `PATCH /scim/v2/{connectionId}/Users/{id}`: `active`, `userName`, `displayName`, `name.*`, `externalId`.
 */
final class PatchUserEndpoint extends UserEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        try {
            $user = $this->users->find($connection, (string) $input->get('id'));
            $wasActive = $user->status !== User::STATUS_DISABLED;
            $user = $this->users->patch($connection, $user, Patch::operations($this->body($input)));
        } catch (ScimError $error) {
            return $this->error($error, $connection, $input);
        }
        $this->audit->record(ReplaceUserEndpoint::transition($wasActive, $user), $connection, $user->id, [], $this->client($input));

        return $this->scim(200, $this->users->resource($connection, $user, $this->location($connection)));
    }
}

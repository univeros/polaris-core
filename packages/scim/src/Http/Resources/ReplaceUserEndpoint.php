<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Model\User;
use Polaris\Scim\AuditNames;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\ScimError;

/**
 * `PUT /scim/v2/{connectionId}/Users/{id}`: the mapped attributes replaced.
 */
final class ReplaceUserEndpoint extends UserEndpoint
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
            $user = $this->users->replace($connection, $user, $this->body($input));
        } catch (ScimError $error) {
            return $this->error($error, $connection, $input);
        }
        $this->audit->record(self::transition($wasActive, $user), $connection, $user->id, [], $this->client($input));

        return $this->scim(200, $this->users->resource($connection, $user, $this->location($connection)));
    }

    public static function transition(bool $wasActive, User $user): string
    {
        $isActive = $user->status !== User::STATUS_DISABLED;

        return match (true) {
            $wasActive && !$isActive => AuditNames::USER_DEACTIVATED,
            !$wasActive && $isActive => AuditNames::USER_REACTIVATED,
            default => AuditNames::USER_UPDATED,
        };
    }
}

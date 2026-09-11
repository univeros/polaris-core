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
 * `DELETE /scim/v2/{connectionId}/Users/{id}`: deprovisioned as the connection says (deactivated, or
 * anonymised); 204.
 */
final class DeleteUserEndpoint extends UserEndpoint
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
        } catch (ScimError $error) {
            return $this->error($error);
        }
        $outcome = $this->users->delete($connection, $user);
        $this->audit->record($outcome === 'deleted' ? AuditNames::USER_DELETED : AuditNames::USER_DEACTIVATED, $connection, $user->id, ['deprovision' => $outcome], $this->client($input));

        return new Result(204, [], ['Content-Type' => self::CONTENT_TYPE]);
    }
}

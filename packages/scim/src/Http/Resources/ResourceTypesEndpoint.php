<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\Groups;
use Polaris\Scim\Http\ScimEndpoint;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Users;

/**
 * `GET /scim/v2/{connectionId}/ResourceTypes`: Users and Groups.
 */
final class ResourceTypesEndpoint extends ScimEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        $connection = $this->connection($input);
        if (!$connection instanceof Connection) {
            return $connection;
        }
        $location = $this->location($connection);
        $types = [
            ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], 'id' => 'User', 'name' => 'User', 'endpoint' => '/Users', 'schema' => Users::SCHEMA, 'meta' => ['resourceType' => 'ResourceType', 'location' => $location . '/ResourceTypes/User']],
            ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], 'id' => 'Group', 'name' => 'Group', 'endpoint' => '/Groups', 'schema' => Groups::SCHEMA, 'meta' => ['resourceType' => 'ResourceType', 'location' => $location . '/ResourceTypes/Group']],
        ];

        return $this->page(['total' => 2, 'resources' => $types], 1);
    }
}

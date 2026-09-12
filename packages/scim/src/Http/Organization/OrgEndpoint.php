<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Organization;

use Polaris\Contract\TokenInterface;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\Connections;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Resources;
use Polaris\Scim\ScimAudit;

/**
 * What the organization's self-service routes share: core's bearer and `org.update` gate the route
 * (the authorization middleware); the organization in the path must be the token's active one (a
 * superadmin excepted), then the connection must belong to it.
 */
abstract class OrgEndpoint extends Endpoint
{
    public function __construct(protected readonly Connections $connections, protected readonly Resources $resources, protected readonly ScimAudit $audit)
    {
    }

    /**
     * @return array{TokenInterface, string}|Result
     */
    protected function organization(Input $input): array|Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $organizationId = (string) $input->get('id');
        if ($organizationId === '' || $this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->problem(403, 'scim/forbidden', 'Forbidden', 'That organization is not your active organization.');
        }

        return [$token, $organizationId];
    }

    protected function connection(Input $input, string $organizationId): Connection|Result
    {
        $connection = $this->connections->find((string) $input->get('connectionId'));
        if (!$connection instanceof Connection || $connection->organizationId !== $organizationId) {
            return $this->problem(404, 'scim/not_found', 'Not found', 'The connection does not exist in this organization.');
        }

        return $connection;
    }

    /**
     * @return array<string, mixed>
     */
    protected function state(Connection $connection): array
    {
        return [...$connection->toArray(), 'sync' => [
            'users' => $this->resources->count($connection, 'User'),
            'groups' => $this->resources->count($connection, 'Group'),
            'provisioned_members' => $this->resources->provisionedUsers($connection),
        ]];
    }
}

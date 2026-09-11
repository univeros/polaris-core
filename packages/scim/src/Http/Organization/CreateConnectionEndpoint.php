<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Scim\AuditNames;
use Polaris\Scim\Model\Connection;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;
use Polaris\Scim\Connections;
use Polaris\Scim\Resources;
use Polaris\Scim\ScimAudit;
use Polaris\Scim\Sp;

use function in_array;
use function is_array;
use function is_string;
use function mb_strlen;
use function trim;

/**
 * `POST /orgs/{id}/scim/connections`: a connection and its token, in this response only.
 */
final class CreateConnectionEndpoint extends OrgEndpoint
{
    public function __construct(Connections $connections, Resources $resources, ScimAudit $audit, private readonly Providers $providers, private readonly Sp $sp)
    {
        parent::__construct($connections, $resources, $audit);
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        [$token, $organizationId] = $scope;
        $name = is_string($input->get('name')) ? trim($input->get('name')) : '';
        if ($name === '' || mb_strlen($name) > 120) {
            return $this->problem(422, 'scim/invalid_input', 'Invalid input', 'name must be 1 to 120 characters.');
        }
        $deprovision = $input->get('deprovision', Connection::DEACTIVATE);
        if (!in_array($deprovision, [Connection::DEACTIVATE, Connection::DELETE], true)) {
            return $this->problem(422, 'scim/invalid_input', 'Invalid input', 'deprovision must be deactivate or delete.');
        }
        $providerId = is_string($input->get('sso_provider_id')) && $input->get('sso_provider_id') !== '' ? (string) $input->get('sso_provider_id') : null;
        if ($providerId !== null) {
            $provider = $this->providers->find($providerId);
            if (!$provider instanceof Provider || $provider->organizationId !== $organizationId) {
                return $this->problem(422, 'scim/invalid_input', 'Invalid input', 'sso_provider_id must be one of the organization\'s providers.');
            }
        }
        [$connection, $secret] = $this->connections->create($organizationId, $name, $deprovision, $providerId, $this->actorId($token));
        $this->audit->recordUser(AuditNames::CONNECTION_CREATED, $this->actorId($token), $connection, ['deprovision' => $deprovision], $this->client($input));

        return $this->respond(201, ['data' => [...$this->state($connection), 'token' => $secret, 'scim_base_url' => $this->sp->location($connection->id)]]);
    }
}

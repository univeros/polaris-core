<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\AuditNames;
use Polaris\Sso\Domains;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;
use Polaris\Sso\SsoAudit;

use function is_array;
use function is_string;
use function preg_match;
use function strtolower;
use function trim;

/**
 * `POST /orgs/{id}/sso/domains`: claims a domain for a provider; verification follows.
 */
final class AddDomainEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Domains $domains, private readonly Providers $providers, private readonly SsoAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }
        [$token, $organizationId] = $scope;
        $domain = is_string($input->get('domain')) ? strtolower(trim($input->get('domain'))) : '';
        if (preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain) !== 1) {
            return $this->invalid('domain must be a hostname (example.com).');
        }
        $provider = $this->providers->find((string) $input->get('provider_id'));
        if (!$provider instanceof Provider || $provider->organizationId !== $organizationId) {
            return $this->invalid('provider_id must be one of the organization\'s providers.');
        }
        if ($this->domains->findByName($domain) !== null) {
            return $this->problem(409, 'sso/conflict', 'Conflict', 'The domain is already claimed.');
        }
        $record = $this->domains->add($organizationId, $provider->id, $domain);
        $this->audit->record(AuditNames::DOMAIN_ADDED, 'user', $this->actorId($token), $record->id, $organizationId, ['domain' => $domain, 'provider_id' => $provider->id], $this->client($input));

        return $this->respond(201, ['data' => $record->toArray()]);
    }
}

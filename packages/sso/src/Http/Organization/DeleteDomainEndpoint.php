<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\AuditNames;
use Polaris\Sso\Domains;
use Polaris\Sso\Model\Domain;
use Polaris\Sso\SsoAudit;

use function is_array;

/**
 * `DELETE /orgs/{id}/sso/domains/{domainId}`.
 */
final class DeleteDomainEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Domains $domains, private readonly SsoAudit $audit)
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
        $domain = $this->domains->find((string) $input->get('domainId'));
        if (!$domain instanceof Domain || $domain->organizationId !== $organizationId) {
            return $this->problem(404, 'sso/not_found', 'Not found', 'The domain does not exist in this organization.');
        }
        $this->domains->delete($domain->id);
        $this->audit->record(AuditNames::DOMAIN_DELETED, 'user', $this->actorId($token), $domain->id, $organizationId, ['domain' => $domain->domain], $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}

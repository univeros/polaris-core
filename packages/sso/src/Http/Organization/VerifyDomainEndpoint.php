<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\AuditNames;
use Polaris\Sso\Domain\DomainVerifier;
use Polaris\Sso\Domains;
use Polaris\Sso\Model\Domain;
use Polaris\Sso\SsoAudit;

use function is_array;

/**
 * `POST /orgs/{id}/sso/domains/{domainId}/verify`: checks the DNS record or the well-known file.
 */
final class VerifyDomainEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Domains $domains, private readonly DomainVerifier $verifier, private readonly SsoAudit $audit)
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
        if ($domain->verifiedAt === null) {
            $method = $this->verifier->verify($domain->domain, $domain->token);
            if ($method === null) {
                return $this->problem(422, 'sso/domain_unverified', 'Domain unverified', 'Neither the DNS record nor the well-known file carries the token yet.');
            }
            $this->domains->markVerified($domain);
            $this->audit->record(AuditNames::DOMAIN_VERIFIED, 'user', $this->actorId($token), $domain->id, $organizationId, ['domain' => $domain->domain, 'method' => $method], $this->client($input));
        }

        return $this->respond(200, ['data' => $domain->toArray()]);
    }
}

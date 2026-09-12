<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Organization;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sso\Domains;
use Polaris\Sso\Model\Domain;

use function array_map;
use function is_array;

/**
 * `GET /orgs/{id}/sso/domains`: the organization's domains with their verification instructions.
 */
final class ListDomainsEndpoint extends OrgEndpoint
{
    public function __construct(private readonly Domains $domains)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = $this->organization($input);
        if (!is_array($scope)) {
            return $scope;
        }

        return $this->respond(200, ['data' => array_map(static fn(Domain $domain): array => $domain->toArray(), $this->domains->forOrganization($scope[1]))]);
    }
}

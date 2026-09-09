<?php

declare(strict_types=1);

namespace Polaris\Http\Orgs;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Authorization\OrganizationService;

/**
 * `GET /orgs` — the organizations the authenticated caller is an active member of.
 */
final class ListOrganizationsEndpoint extends Endpoint
{
    public function __construct(private readonly OrganizationService $organizations)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        if ($userId === '') {
            return $this->unauthorized();
        }

        $data = [];
        foreach ($this->organizations->listForUser($userId) as $organization) {
            $data[] = [
                'id' => $organization->id,
                'name' => $organization->name,
                'slug' => $organization->slug,
            ];
        }

        return $this->respond(200, ['data' => $data]);
    }
}

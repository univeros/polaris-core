<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Audit;

use Override;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Organizations;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Audit\Drain\Drains;
use Polaris\Audit\Model\AuditDrain;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_map;

/**
 * `GET /admin/organizations/{id}/drains`: the organization's audit drains (never their secrets).
 */
final class ListDrainsEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Organizations $organizations, private readonly Drains $drains)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $organizationId = (string) $input->get('id');
        $principal = $this->authorize($input, Capability::Read, $organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        if ($this->organizations->find($organizationId) === null) {
            return $this->missing('The organization does not exist.');
        }

        return $this->respond(200, ['data' => array_map(static fn(AuditDrain $drain): array => $drain->toArray(), $this->drains->forOrganization($organizationId))]);
    }
}

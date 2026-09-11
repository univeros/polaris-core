<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Grants;

use Override;
use Polaris\Admin\Grants;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Model\AdminGrant;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_map;

/**
 * `GET /admin/grants`: every admin grant.
 */
final class ListGrantsEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Grants $grants)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Own);
        if (!$principal instanceof Principal) {
            return $principal;
        }

        return $this->respond(200, ['data' => array_map(static fn(AdminGrant $grant): array => $grant->toArray(), $this->grants->all())]);
    }
}

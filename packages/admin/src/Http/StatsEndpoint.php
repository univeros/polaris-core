<?php

declare(strict_types=1);

namespace Polaris\Admin\Http;

use Override;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Stats;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /admin/stats`: totals and the last day, week and month, for instance-scoped operators.
 */
final class StatsEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Stats $stats)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }

        return $this->respond(200, ['data' => $this->stats->snapshot()]);
    }
}

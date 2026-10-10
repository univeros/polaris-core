<?php

declare(strict_types=1);

namespace Polaris\Agents\Http\Admin;

use Override;
use Polaris\Admin\Http\AdminRoute;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Agents\Agents;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /admin/agents`: every agent the operator's scope covers.
 */
final class AdminListAgentsEndpoint extends Endpoint
{
    use AdminRoute;

    public function __construct(private readonly Agents $agents)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $data = [];
        foreach ($this->agents->all() as $agent) {
            if ($principal->covers($agent->organizationId)) {
                $data[] = $agent->toArray();
            }
        }

        return $this->respond(200, ['data' => $data]);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Agents\Http;

use Override;
use Polaris\Agents\Hosts;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Host;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_map;

/**
 * `GET /agents/hosts`: the caller's live hosts, and their active organization's when they may update it.
 */
final class ListHostsEndpoint extends AgentsEndpoint
{
    public function __construct(private readonly Hosts $hosts, private readonly Gate $gate)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $hosts = $this->hosts->forOwner(Agent::OWNER_USER, $this->actorId($token));
        $organizationId = $this->actorOrg($token);
        if ($organizationId !== null && $this->gate->allows($token, self::ORGANIZATION_PERMISSION)) {
            $hosts = [...$hosts, ...$this->hosts->forOwner(Agent::OWNER_ORGANIZATION, $organizationId)];
        }

        return $this->respond(200, ['data' => array_map(static fn(Host $host): array => $host->toArray(), $hosts)]);
    }
}

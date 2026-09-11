<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Http\Admin;

use Override;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sentinel\IpRules;
use Polaris\Sentinel\Model\IpRule;

use function array_map;

/**
 * `GET /admin/sentinel/ip-rules`: every rule, in the order they match.
 */
final class ListIpRulesEndpoint extends SentinelAdminEndpoint
{
    public function __construct(private readonly IpRules $rules)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Read);
        if (!$principal instanceof Principal) {
            return $principal;
        }

        return $this->respond(200, ['data' => array_map(static fn(IpRule $rule): array => $rule->toArray(), $this->rules->all())]);
    }
}

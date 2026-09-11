<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Http\Admin;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sentinel\AuditNames;
use Polaris\Sentinel\IpRules;

/**
 * `DELETE /admin/sentinel/ip-rules/{id}`: the rule stops matching at once.
 */
final class DeleteIpRuleEndpoint extends SentinelAdminEndpoint
{
    public function __construct(private readonly IpRules $rules, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Own);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $id = (string) $input->get('id');
        if (!$this->rules->remove($id)) {
            return $this->missing('The rule does not exist.');
        }
        $this->audit->record(AuditNames::IP_RULE_DELETED, $principal, $id, client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'deleted']]);
    }
}

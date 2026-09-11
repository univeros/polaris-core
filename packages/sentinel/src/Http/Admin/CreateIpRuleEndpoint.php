<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Http\Admin;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\IpAllowlist;
use Polaris\Admin\Principal\Principal;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Sentinel\AuditNames;
use Polaris\Sentinel\IpRules;
use Polaris\Sentinel\Model\IpRule;

use function in_array;
use function is_string;
use function mb_strlen;
use function trim;

/**
 * `POST /admin/sentinel/ip-rules`: an allow or block rule for an address or a CIDR block.
 */
final class CreateIpRuleEndpoint extends SentinelAdminEndpoint
{
    private const int MAX_NOTE = 255;

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
        $cidr = is_string($input->get('cidr')) ? trim($input->get('cidr')) : '';
        if ($cidr === '' || !IpAllowlist::isValid($cidr)) {
            return $this->invalid('cidr must be an IP address or a CIDR block.');
        }
        $action = $input->get('action');
        if (!in_array($action, [IpRule::ALLOW, IpRule::BLOCK], true)) {
            return $this->invalid('action must be allow or block.');
        }
        $note = self::text($input->get('note'));
        if ($note !== null && mb_strlen($note) > self::MAX_NOTE) {
            return $this->invalid('note must be at most 255 characters.');
        }
        $rule = $this->rules->add($cidr, $action, $note, $principal->id);
        $this->audit->record(AuditNames::IP_RULE_CREATED, $principal, $rule->id, data: ['cidr' => $cidr, 'action' => $action], client: $this->client($input));

        return $this->respond(201, ['data' => $rule->toArray()]);
    }
}

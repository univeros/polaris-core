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
use Polaris\Sentinel\Engine;

use function hash;
use function is_string;
use function str_contains;
use function strtolower;
use function trim;

/**
 * `POST /admin/sentinel/unblock`: clears what the resettable signals counted for an email or an address.
 */
final class UnblockEndpoint extends SentinelAdminEndpoint
{
    public function __construct(private readonly Engine $engine, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Support);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $identifier = is_string($input->get('identifier')) ? strtolower(trim($input->get('identifier'))) : '';
        if ($identifier === '') {
            return $this->invalid('identifier must be an email or an IP address.');
        }
        $this->engine->unblock($identifier);
        $this->audit->record(AuditNames::UNBLOCKED, $principal, data: ['identifier_hash' => hash('sha256', $identifier), 'kind' => str_contains($identifier, '@') ? 'email' : 'ip'], client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'unblocked', 'identifier' => $identifier]]);
    }
}

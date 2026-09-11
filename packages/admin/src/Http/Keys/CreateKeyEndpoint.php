<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Keys;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Keys;
use Polaris\Admin\Organizations;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\IpAllowlist;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Http\Input;
use Polaris\Http\Result;

use function array_values;
use function is_array;
use function is_string;
use function mb_strlen;
use function trim;

/**
 * `POST /admin/keys`: an API key for a dashboard or an integration; the secret is in this response only.
 */
final class CreateKeyEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Keys $keys, private readonly Organizations $organizations, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $scope = self::text($input->get('scope')) ?? Principal::SCOPE_INSTANCE;
        $principal = $this->authorize($input, Capability::Own, $scope === Principal::SCOPE_INSTANCE ? null : $scope);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $name = is_string($input->get('name')) ? trim($input->get('name')) : '';
        if ($name === '' || mb_strlen($name) > 120) {
            return $this->invalid('name must be 1 to 120 characters.');
        }
        $role = Role::tryFromInput($input->get('role'));
        if ($role === null) {
            return $this->invalid('role must be viewer, support, admin or owner.');
        }
        $allowlist = $input->get('ip_allowlist', []);
        if (!is_array($allowlist)) {
            return $this->invalid('ip_allowlist must be a list of addresses or CIDR blocks.');
        }
        foreach ($allowlist as $entry) {
            if (!is_string($entry) || !IpAllowlist::isValid($entry)) {
                return $this->invalid('ip_allowlist must be a list of addresses or CIDR blocks.');
            }
        }
        $expiresAt = self::datetime($input->get('expires_at'));
        if ($expiresAt === false) {
            return $this->invalid('expires_at must be an ISO-8601 datetime.');
        }
        if ($scope !== Principal::SCOPE_INSTANCE && $this->organizations->find($scope) === null) {
            return $this->invalid('scope must be "instance" or an organization id.');
        }
        $issued = $this->keys->create($name, $role, $scope, array_values($allowlist), $expiresAt, $principal->id);
        $this->audit->record(AdminAudit::KEY_CREATED, $principal, $issued->key->id, $scope === Principal::SCOPE_INSTANCE ? null : $scope, ['name' => $name, 'role' => $role->value], $this->client($input));

        return $this->respond(201, ['data' => [...$issued->key->toArray(), 'key' => $issued->plaintext]]);
    }
}

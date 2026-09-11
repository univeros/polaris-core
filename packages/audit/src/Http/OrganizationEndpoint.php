<?php

declare(strict_types=1);

namespace Polaris\Audit\Http;

use Override;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /audit/organization/{id}`: the organization's events for a member with `audit.read`, on the
 * caller's active organization only (a token scoped to org A cannot read org B).
 */
final class OrganizationEndpoint extends AuditEndpoint
{
    public const array REQUIRES_PERMISSIONS = [PermissionCatalog::AUDIT_READ];

    public function __construct(private readonly Store $store)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $organizationId = (string) $input->get('id');
        if ($organizationId === '' || $this->deniesActiveOrg($input, $token, $organizationId)) {
            return $this->problem(403, 'audit/forbidden', 'Forbidden', 'That organization is not your active organization.');
        }
        $query = $this->query($input, organizationId: $organizationId);
        if (!$query instanceof AuditQuery) {
            return $query;
        }

        return $this->respond(200, $this->store->read($query)->toArray());
    }
}

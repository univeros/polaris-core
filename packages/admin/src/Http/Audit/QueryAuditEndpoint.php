<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Audit;

use Override;
use Polaris\Admin\Http\AdminRoute;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Principals;
use Polaris\Audit\Http\AuditEndpoint;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /admin/audit`: the instance-wide trail with the audit routes' filters plus `actor_id`,
 * `subject_id` and `organization_id`; an organization-scoped operator sees their organization only.
 */
final class QueryAuditEndpoint extends AuditEndpoint
{
    use AdminRoute;

    public function __construct(private readonly Store $store)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $organizationId = self::text($input->get('organization_id'));
        $caller = $input->attribute(Principals::ATTRIBUTE);
        if ($organizationId === null && $caller instanceof Principal && $caller->scope !== Principal::SCOPE_INSTANCE) {
            $organizationId = $caller->scope;
        }
        $principal = $this->authorize($input, Capability::Read, $organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $query = $this->query($input, organizationId: $organizationId);
        if (!$query instanceof AuditQuery) {
            return $query;
        }
        $query = new AuditQuery(
            names: $query->names,
            actorId: self::text($input->get('actor_id')),
            subjectId: self::text($input->get('subject_id')),
            organizationId: $query->organizationId,
            from: $query->from,
            to: $query->to,
            cursor: $query->cursor,
            limit: $query->limit,
        );

        return $this->respond(200, $this->store->read($query)->toArray());
    }
}

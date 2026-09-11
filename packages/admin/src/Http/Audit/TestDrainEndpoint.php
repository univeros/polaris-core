<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Audit;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Audit\Drain\Drains;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /admin/organizations/{id}/drains/{drainId}/test`: records `admin.drain_tested` for the
 * organization, which the audit plugin delivers to its drains like any event, and answers the drain's
 * delivery state afterwards (`last_delivery_at`, `last_error`).
 */
final class TestDrainEndpoint extends AdminEndpoint
{
    public function __construct(private readonly Drains $drains, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $organizationId = (string) $input->get('id');
        $principal = $this->authorize($input, Capability::Own, $organizationId);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $drainId = (string) $input->get('drainId');
        $drain = $this->drains->find($drainId);
        if ($drain === null || $drain->organizationId !== $organizationId) {
            return $this->missing('The drain does not exist for this organization.');
        }
        $this->audit->record(AdminAudit::DRAIN_TESTED, $principal, null, $organizationId, ['drain_id' => $drainId], $this->client($input));
        $after = $this->drains->find($drainId) ?? $drain;

        return $this->respond(200, ['data' => $after->toArray()]);
    }
}

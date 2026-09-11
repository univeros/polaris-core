<?php

declare(strict_types=1);

namespace Polaris\Admin\Http\Mfa;

use Override;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\Http\AdminEndpoint;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Exception\LastFactorProtectedException;
use Polaris\Exception\MfaFactorNotFoundException;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Mfa\MfaManagementService;

/**
 * `DELETE /admin/users/{id}/mfa/{factorId}`: removes one factor; the last confirmed factor of a user
 * under enforced MFA stays (reset the MFA instead).
 */
final class RemoveFactorEndpoint extends AdminEndpoint
{
    public function __construct(private readonly MfaManagementService $mfa, private readonly AdminAudit $audit)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $principal = $this->authorize($input, Capability::Manage);
        if (!$principal instanceof Principal) {
            return $principal;
        }
        $userId = (string) $input->get('id');
        $factorId = (string) $input->get('factorId');
        try {
            $this->mfa->remove($userId, $factorId);
        } catch (MfaFactorNotFoundException $exception) {
            return $this->missing($exception->getMessage());
        } catch (LastFactorProtectedException $exception) {
            return $this->conflict($exception->getMessage());
        }
        $this->audit->record(AdminAudit::MFA_FACTOR_REMOVED, $principal, $userId, data: ['factor_id' => $factorId], client: $this->client($input));

        return $this->respond(200, ['data' => ['status' => 'removed']]);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Exception\LastFactorProtectedException;
use Polaris\Exception\MfaFactorNotFoundException;
use Polaris\Mfa\MfaManagementService;

use function trim;

/**
 * `DELETE /auth/mfa/factors/{id}` — remove one of the authenticated user's factors (spec §8).
 * Step-up gated (enforced by `StepUpMiddleware`); removing the
 * last confirmed factor is blocked while MFA is enforced for the user (`409`).
 */
final class DeleteFactorEndpoint extends Endpoint
{
    public function __construct(private readonly MfaManagementService $service)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        if ($userId === '') {
            return $this->unauthorized();
        }

        $factorId = trim((string) $input->get('id', ''));
        if ($factorId === '') {
            return $this->unprocessable(['A factor id is required.']);
        }

        try {
            $this->service->remove($userId, $factorId);
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (LastFactorProtectedException $exception) {
            return $this->respond(409, ['error' => 'last_factor_protected', 'message' => $exception->getMessage()]);
        }

        return $this->respond(200, ['data' => ['status' => 'removed']]);
    }
}

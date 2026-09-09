<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Mfa\RecoveryCodeService;

/**
 * `POST /auth/mfa/recovery-codes/regenerate` — retire the user's prior recovery codes and return a
 * fresh batch (spec §6). Step-up gated: the route is guarded by
 * `StepUpMiddleware`, so a stale session is rejected with
 * `401 step_up_required` before this domain runs — the regeneration itself just needs the
 * authenticated user.
 */
final class RegenerateRecoveryCodesEndpoint extends Endpoint
{
    public function __construct(private readonly RecoveryCodeService $recoveryCodes)
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

        return $this->respond(200, ['data' => ['recovery_codes' => $this->recoveryCodes->regenerate($userId)]]);
    }
}

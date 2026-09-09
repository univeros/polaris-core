<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Exception\InvalidOtpException;
use Polaris\Exception\MfaFactorNotFoundException;
use Polaris\Mfa\OtpFactorService;

use function trim;

/**
 * `POST /auth/mfa/{sms,email}/confirm {factor_id, code}` — confirm a pending SMS or email factor
 * with the delivered code. One domain serves both channels: {@see OtpFactorService} resolves the
 * factor by id and verifies the code against that factor's own challenge — so the route the caller
 * hits is irrelevant to safety (they must hold the code delivered to that factor either way). On
 * the user's first confirmed factor the response also carries the one-time recovery codes.
 */
final class OtpFactorConfirmEndpoint extends Endpoint
{
    public function __construct(private readonly OtpFactorService $service)
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

        $factorId = trim((string) $input->get('factor_id', ''));
        $code = trim((string) $input->get('code', ''));
        if ($factorId === '' || $code === '') {
            return $this->unprocessable(['A factor id and verification code are required.']);
        }

        try {
            $result = $this->service->confirm($userId, $factorId, $code);
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (InvalidOtpException) {
            return $this->respond(422, ['error' => 'invalid_code', 'message' => 'The verification code is invalid.']);
        }

        $data = ['status' => 'confirmed'];
        if ($result->recoveryCodes !== []) {
            $data['recovery_codes'] = $result->recoveryCodes;
        }

        return $this->respond(200, ['data' => $data]);
    }
}

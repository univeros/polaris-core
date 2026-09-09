<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Exception\InvalidOtpException;
use Polaris\Exception\MfaFactorNotFoundException;
use Polaris\Exception\OtpCooldownException;
use Polaris\Identity\StepUpService;

use function trim;

/**
 * `POST /auth/mfa/step-up/challenge {factor_id}` — while logged in, send the `step_up` OTP for an
 * sms/email factor so the user can re-authenticate. Authenticated by the normal access token (the
 * caller is already logged in); TOTP factors take their code from the app, so a challenge for one
 * is a `422`.
 */
final class StepUpChallengeEndpoint extends Endpoint
{
    public function __construct(private readonly StepUpService $service)
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
        if ($factorId === '') {
            return $this->unprocessable(['A factor id is required.']);
        }

        try {
            $result = $this->service->challenge($userId, $factorId, $this->client($input));
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (OtpCooldownException) {
            return $this->respond(429, [
                'error' => 'too_many_requests',
                'message' => 'Please wait before requesting another code.',
            ]);
        } catch (InvalidOtpException) {
            return $this->respond(422, [
                'error' => 'unsupported_factor',
                'message' => 'This factor does not use a sent challenge.',
            ]);
        }

        return $this->respond(200, [
            'data' => ['channel' => $result->channel, 'destination' => $result->maskedDestination],
        ]);
    }
}

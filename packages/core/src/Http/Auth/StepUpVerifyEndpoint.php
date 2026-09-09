<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Exception\InvalidGrantException;
use Polaris\Exception\InvalidOtpException;
use Polaris\Exception\MfaFactorNotFoundException;
use Polaris\Identity\StepUpService;

use function is_string;
use function trim;

/**
 * `POST /auth/mfa/step-up {factor_id?, code, type?}` — re-verify a factor (or a recovery code) while
 * logged in and receive a **refreshed access token** for the same session, with a recent `auth_time`
 * so a step-up-gated operation can proceed. Authenticated by the normal access token; the new token
 * is bound to that token's session (`sid`).
 */
final class StepUpVerifyEndpoint extends Endpoint
{
    private const string TYPE_RECOVERY = 'recovery';

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
        $sessionId = (string) $token->getMetadata('sid');
        if ($userId === '' || $sessionId === '') {
            return $this->unauthorized();
        }

        $code = trim((string) $input->get('code', ''));
        if ($code === '') {
            return $this->unprocessable(['A verification code is required.']);
        }

        try {
            $accessToken = $this->service->verify(
                $userId,
                $this->organizationId($token->getMetadata('org')),
                $sessionId,
                $this->factorId($input),
                $code,
            );
        } catch (MfaFactorNotFoundException) {
            return $this->respond(404, ['error' => 'not_found', 'message' => 'MFA factor not found.']);
        } catch (InvalidOtpException) {
            return $this->respond(422, ['error' => 'invalid_code', 'message' => 'The verification code is invalid.']);
        } catch (InvalidGrantException) {
            // The session ended (logout) while its access token was still valid — re-login required.
            return $this->unauthorized();
        }

        return $this->respond(200, ['data' => ['access_token' => $accessToken, 'token_type' => 'Bearer']]);
    }

    private function organizationId(mixed $org): ?string
    {
        return is_string($org) && $org !== '' ? $org : null;
    }

    /**
     * The factor to verify against, or null for the recovery-code path (`type=recovery` or no id).
     */
    private function factorId(Input $input): ?string
    {
        if (trim((string) $input->get('type', '')) === self::TYPE_RECOVERY) {
            return null;
        }

        $factorId = trim((string) $input->get('factor_id', ''));

        return $factorId === '' ? null : $factorId;
    }
}

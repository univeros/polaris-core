<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Model\MfaFactor;
use Polaris\Model\User;
use Polaris\Exception\OtpCooldownException;
use Polaris\Mfa\E164;
use Polaris\Mfa\OtpFactorService;
use Polaris\Repository\UserRepository;

use function trim;

/**
 * `POST /auth/mfa/sms/enroll {phone_e164}` — start SMS factor enrollment: validate the E.164
 * number, create an unconfirmed factor, and text a code. Responds with the factor id and the
 * masked destination; confirm at `/auth/mfa/sms/confirm`.
 */
final class SmsEnrollEndpoint extends Endpoint
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly OtpFactorService $service,
    ) {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        $userId = (string) $token->getMetadata('sub');
        $user = $userId === '' ? null : $this->users->find($userId);
        if (!$user instanceof User) {
            return $this->unauthorized();
        }

        $phone = trim((string) $input->get('phone_e164', ''));
        if (!E164::isValid($phone)) {
            return $this->unprocessable(['A valid E.164 phone number is required.']);
        }

        try {
            $result = $this->service->enroll($user, MfaFactor::TYPE_SMS, $phone, $this->client($input));
        } catch (OtpCooldownException) {
            return $this->respond(429, ['error' => 'rate_limited', 'message' => 'Please wait before requesting another code.']);
        }

        return $this->respond(200, [
            'data' => ['factor_id' => $result->factorId, 'destination' => $result->maskedDestination],
        ]);
    }
}

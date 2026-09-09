<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Model\User;
use Polaris\Mfa\MfaTotpService;
use Polaris\Repository\UserRepository;

/**
 * `POST /auth/mfa/totp/enroll` — start authenticator-app enrollment for the authenticated user:
 * returns the (unconfirmed) factor id, the base32 secret and `otpauth://` URI for manual/scan
 * setup, and a rendered QR. The secret is shown only here, until the factor is confirmed.
 */
final class TotpEnrollEndpoint extends Endpoint
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly MfaTotpService $service,
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

        $result = $this->service->enroll($user);

        return $this->respond(200, [
            'data' => [
                'factor_id' => $result->factorId,
                'secret' => $result->secret,
                'otpauth_uri' => $result->otpauthUri,
                'qr_svg' => $result->qrSvg,
            ],
        ]);
    }
}

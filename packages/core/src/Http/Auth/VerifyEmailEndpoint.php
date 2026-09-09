<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Exception\InvalidVerificationTokenException;
use Polaris\Identity\EmailVerificationService;

use function trim;

/**
 * `POST /auth/email/verify` — confirms an email address from its token. Idempotent: a
 * token for an already-verified user still returns `200`. A bad/expired token returns a
 * generic `400` that reveals nothing about which condition failed.
 */
final class VerifyEmailEndpoint extends Endpoint
{
    public function __construct(private readonly EmailVerificationService $verifications)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = trim((string) $input->get('token', ''));

        if ($token === '') {
            return $this->unprocessable(['A verification token is required.']);
        }

        try {
            $this->verifications->verify($token);
        } catch (InvalidVerificationTokenException) {
            return $this->respond(400, ['message' => 'The verification token is invalid or has expired.']);
        }

        return $this->respond(200, ['message' => 'Email verified.']);
    }
}

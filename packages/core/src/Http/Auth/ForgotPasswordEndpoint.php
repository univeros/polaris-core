<?php

declare(strict_types=1);

namespace Polaris\Http\Auth;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Override;
use Polaris\Identity\PasswordResetService;

use function trim;

/**
 * `POST /auth/password/forgot` — request a password reset. Always a generic `202`;
 * internally a reset challenge is created only for a known, active account.
 */
final class ForgotPasswordEndpoint extends Endpoint
{
    private const string GENERIC =
        'If an account exists for that address, a password reset link has been sent.';

    public function __construct(private readonly PasswordResetService $passwords)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $email = trim((string) $input->get('email', ''));

        if ($email === '' || !$this->isEmail($email)) {
            return $this->unprocessable(['A valid email address is required.']);
        }

        $this->passwords->forgot($email, $this->client($input));

        return $this->respond(202, ['message' => self::GENERIC]);
    }
}

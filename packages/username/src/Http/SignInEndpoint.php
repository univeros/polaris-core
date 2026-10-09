<?php

declare(strict_types=1);

namespace Polaris\Username\Http;

use Override;
use Polaris\Exception\AccountDisabledException;
use Polaris\Exception\EmailNotVerifiedException;
use Polaris\Exception\InvalidCredentialsException;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Identity\LoginResult;
use Polaris\Identity\LoginService;
use Polaris\Identity\MfaChallengeResult;
use Polaris\Identity\MfaFactorView;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Username\Usernames;

use function array_map;
use function is_string;
use function str_contains;
use function trim;

/**
 * `POST /username/sign-in`: a username (or an email) and the password, through core's password path, so
 * lockout, the MFA gate, timing parity and the envelope are core's. An unknown username is looked up as
 * an address that cannot exist, so it costs the same dummy verify as an unknown email.
 */
final class SignInEndpoint extends Endpoint
{
    private const string NOBODY = 'nobody@username.invalid';

    public function __construct(private readonly LoginService $login, private readonly Usernames $usernames, private readonly UserRepository $users)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $identifier = $input->get('username');
        $password = $input->get('password');
        if (!is_string($identifier) || trim($identifier) === '' || !is_string($password) || $password === '') {
            return $this->problem(422, 'username/invalid_input', 'Invalid input', 'A username (or email) and a password are required.');
        }
        try {
            $result = $this->login->login($this->email(trim($identifier)), $password, $this->client($input));
        } catch (EmailNotVerifiedException) {
            return $this->problem(403, 'username/email_unverified', 'Email not verified', 'Verify your email address before signing in.');
        } catch (AccountDisabledException) {
            return $this->problem(403, 'username/account_disabled', 'Account disabled', 'This account is disabled.');
        } catch (InvalidCredentialsException) {
            return $this->problem(401, 'username/invalid_credentials', 'Invalid credentials', 'Invalid username or password.');
        }

        return $this->respond(200, ['data' => $result instanceof MfaChallengeResult ? self::mfa($result) : self::session($result)]);
    }

    private function email(string $identifier): string
    {
        if (str_contains($identifier, '@')) {
            return $identifier;
        }
        $userId = $this->usernames->userId($identifier);
        $user = $userId === null ? null : $this->users->find($userId);

        return $user instanceof User ? $user->email : self::NOBODY;
    }

    /**
     * @return array<string, mixed>
     */
    private static function session(LoginResult $result): array
    {
        return [
            'access_token' => $result->tokens->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $result->tokens->accessExpiresIn,
            'refresh_token' => $result->tokens->refreshToken,
            'user' => ['id' => $result->userId, 'email' => $result->email, 'email_verified' => $result->emailVerified],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function mfa(MfaChallengeResult $result): array
    {
        return [
            'mfa_required' => true,
            'mfa_token' => $result->mfaToken,
            'factors' => array_map(static fn(MfaFactorView $factor): array => $factor->toArray(), $result->factors),
        ];
    }
}

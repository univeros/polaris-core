<?php

declare(strict_types=1);

namespace Polaris\Social\Http;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Social\SocialException;

use function is_string;
use function trim;

/**
 * What every social route shares: the problem document for a refused step and the input helpers.
 */
abstract class SocialEndpoint extends Endpoint
{
    protected function refuse(SocialException $exception): Result
    {
        return match ($exception->reason) {
            SocialException::PROVIDER_NOT_FOUND => $this->problem(404, 'social/provider_not_found', 'Provider not found', 'No such provider is configured.'),
            SocialException::REDIRECT_NOT_ALLOWED => $this->problem(422, 'social/redirect_not_allowed', 'Redirect not allowed', $exception->detail),
            SocialException::STATE_INVALID => $this->problem(422, 'social/state_invalid', 'Invalid state', 'The state is unknown, used, expired or not signed for this application.'),
            SocialException::PROVIDER_ERROR => $this->problem(403, 'social/provider_error', 'Sign-in refused', 'The sign-in could not be completed with the provider.'),
            SocialException::TOKEN_INVALID => $this->problem(422, 'social/token_invalid', 'Invalid token', 'The token could not be verified.'),
            SocialException::EMAIL_REQUIRED => $this->problem(422, 'social/email_required', 'Email required', $exception->detail),
            SocialException::EMAIL_MISMATCH => $this->problem(409, 'social/email_mismatch', 'Email mismatch', $exception->detail),
            SocialException::ACCOUNT_EXISTS => $this->problem(409, 'social/account_exists', 'Account exists', 'An account with this email exists; sign in and link the provider from your account.'),
            SocialException::ACCOUNT_LINKED => $this->problem(409, 'social/account_linked', 'Account linked elsewhere', $exception->detail),
            SocialException::ACCOUNT_DISABLED => $this->problem(403, 'social/account_disabled', 'Account disabled', 'This account is disabled.'),
            SocialException::EMAIL_UNVERIFIED => $this->problem(403, 'social/email_unverified', 'Email not verified', $exception->detail),
            SocialException::NOT_LINKED => $this->problem(404, 'social/not_linked', 'Not linked', $exception->detail),
            SocialException::LAST_CREDENTIAL => $this->problem(409, 'social/last_credential', 'Last credential', $exception->detail),
            SocialException::CODE_INVALID => $this->problem(422, 'social/code_invalid', 'Invalid code', 'The code is unknown, used or expired.'),
            SocialException::NO_REFRESH => $this->problem(409, 'social/no_refresh', 'Token expired', $exception->detail),
            default => $this->problem(422, 'social/invalid_input', 'Invalid input', $exception->detail, ['errors' => [$exception->detail]]),
        };
    }

    protected function invalid(string $message): Result
    {
        return $this->problem(422, 'social/invalid_input', 'Invalid input', $message, ['errors' => [$message]]);
    }

    protected static function text(Input $input, string $field): ?string
    {
        $value = $input->get($field);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    protected static function provider(Input $input): string
    {
        return (string) $input->get('provider');
    }
}

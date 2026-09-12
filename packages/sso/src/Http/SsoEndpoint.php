<?php

declare(strict_types=1);

namespace Polaris\Sso\Http;

use Polaris\Http\Endpoint;
use Polaris\Http\Result;
use Polaris\Sso\SsoException;

/**
 * What every sso route shares: the problem document for a refused step. A rejected assertion or token
 * answers a generic detail; the reason is in the audit trail.
 */
abstract class SsoEndpoint extends Endpoint
{
    protected function refuse(SsoException $exception): Result
    {
        return match ($exception->reason) {
            SsoException::PROVIDER_NOT_FOUND => $this->problem(404, 'sso/provider_not_found', 'Provider not found', 'No SSO provider answers this request.'),
            SsoException::PROVIDER_DISABLED => $this->problem(403, 'sso/provider_disabled', 'Provider disabled', 'The SSO provider is disabled.'),
            SsoException::INVALID_INPUT => $this->problem(422, 'sso/invalid_input', 'Invalid input', $exception->detail),
            SsoException::USER_UNKNOWN => $this->problem(403, 'sso/user_unknown', 'Unknown user', 'No account matches this identity and the provider does not create accounts.'),
            SsoException::ACCOUNT_DISABLED => $this->problem(403, 'sso/account_disabled', 'Account disabled', 'This account is disabled.'),
            SsoException::MEMBERSHIP_SUSPENDED => $this->problem(403, 'sso/membership_suspended', 'Membership suspended', 'Your membership in this organization is suspended.'),
            SsoException::CODE_INVALID => $this->problem(422, 'sso/code_invalid', 'Invalid code', 'The code is unknown, already used or expired.'),
            default => $this->problem(403, 'sso/assertion_invalid', 'Sign-in refused', 'The sign-in could not be completed.'),
        };
    }

    protected static function text(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}

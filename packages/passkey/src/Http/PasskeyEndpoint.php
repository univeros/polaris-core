<?php

declare(strict_types=1);

namespace Polaris\Passkey\Http;

use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passkey\PasskeyException;

use function is_array;
use function is_string;
use function json_encode;
use function trim;

use const JSON_THROW_ON_ERROR;

/**
 * What every passkey route shares: the problem document for a refused step and the credential as the
 * browser produced it (the `PublicKeyCredential` JSON, sent as an object or as its string).
 */
abstract class PasskeyEndpoint extends Endpoint
{
    protected function refuse(PasskeyException $exception): Result
    {
        return match ($exception->reason) {
            PasskeyException::ORIGIN_MISMATCH => $this->problem(403, 'passkey/origin_mismatch', 'Origin mismatch', $exception->detail),
            PasskeyException::CHALLENGE_INVALID => $this->problem(422, 'passkey/challenge_invalid', 'Invalid challenge', 'The challenge is unknown, used or expired.'),
            PasskeyException::CREDENTIAL_INVALID => $this->problem(422, 'passkey/credential_invalid', 'Invalid credential', 'The credential could not be verified.'),
            PasskeyException::ACCOUNT_DISABLED => $this->problem(403, 'passkey/account_disabled', 'Account disabled', 'This account is disabled.'),
            PasskeyException::EMAIL_UNVERIFIED => $this->problem(403, 'passkey/email_unverified', 'Email not verified', $exception->detail),
            PasskeyException::USER_VERIFICATION_REQUIRED => $this->problem(403, 'passkey/user_verification_required', 'User verification required', $exception->detail),
            PasskeyException::NOT_FOUND => $this->problem(404, 'passkey/not_found', 'Passkey not found', 'No such passkey.'),
            PasskeyException::LAST_FACTOR => $this->problem(409, 'passkey/last_factor', 'Last factor', $exception->detail),
            default => $this->problem(422, 'passkey/invalid_input', 'Invalid input', $exception->detail, ['errors' => [$exception->detail]]),
        };
    }

    protected function invalid(string $message): Result
    {
        return $this->problem(422, 'passkey/invalid_input', 'Invalid input', $message, ['errors' => [$message]]);
    }

    protected static function credential(Input $input): ?string
    {
        $credential = $input->get('credential');
        if (is_array($credential)) {
            return json_encode($credential, JSON_THROW_ON_ERROR);
        }

        return is_string($credential) && trim($credential) !== '' ? $credential : null;
    }

    protected static function name(Input $input): ?string
    {
        $name = $input->get('name');

        return is_string($name) ? $name : null;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use Polaris\Messaging\Message;
use Polaris\Messaging\Sender;
use Polaris\Mfa\E164;
use Polaris\Model\User;
use Polaris\Passwordless\Model\Secret;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;
use SensitiveParameter;

use function preg_replace;

/**
 * Phone numbers as a second verified contact and a sign-in identifier: a signed-in user adds one
 * (`add` sends a code, `confirm` attaches it), and later signs in with a code sent to it. An unknown
 * number never creates an account.
 */
final class PhoneSignIn
{
    public const string AMR = 'phone';

    public function __construct(
        private readonly Settings $settings,
        private readonly SecretStore $secrets,
        private readonly Phones $phones,
        private readonly Sessions $sessions,
        private readonly Sender $sender,
        private readonly UserRepository $users,
    ) {
    }

    /**
     * The number in E.164 (`+15551234567`), spaces, dashes and parentheses removed.
     *
     * @throws PasswordlessException not a number
     */
    public static function normalize(string $phone): string
    {
        $e164 = (string) preg_replace('/[\s().-]/', '', $phone);
        if (!E164::isValid($e164)) {
            throw new PasswordlessException(PasswordlessException::INVALID_INPUT, 'phone must be an E.164 number, +15551234567.', ['phone must be an E.164 number, +15551234567.']);
        }

        return $e164;
    }

    /**
     * Sends a sign-in code when the number is an active user's verified phone; the caller answers the
     * same either way.
     *
     * @throws PasswordlessException not a number
     */
    public function send(string $phone): void
    {
        $e164 = self::normalize($phone);
        $userId = $this->phones->owner($e164);
        $user = $userId === null ? null : $this->users->find($userId);
        if (!$user instanceof User || $user->status === User::STATUS_DISABLED) {
            return;
        }
        $this->sendCode(Secret::PHONE_SIGN_IN, $e164, $user->id);
    }

    /**
     * @return array<string, mixed> the envelope's `data`
     * @throws PasswordlessException
     */
    public function signIn(string $phone, #[SensitiveParameter] string $code, ClientContext $client): array
    {
        $e164 = self::normalize($phone);
        $secret = $this->secrets->spendCode(Secret::PHONE_SIGN_IN, $e164, $code);
        $user = $secret?->userId === null ? null : $this->sessions->active($secret->userId);
        if (!$user instanceof User || $this->phones->owner($e164) !== $user->id) {
            throw PasswordlessException::codeInvalid();
        }

        return $this->sessions->open($user, [self::AMR], $client);
    }

    /**
     * Sends a confirmation code to a number the user wants to add, unless another account has it; the
     * caller answers the same either way.
     *
     * @throws PasswordlessException not a number
     */
    public function add(string $userId, string $phone): void
    {
        $e164 = self::normalize($phone);
        $owner = $this->phones->owner($e164);
        if ($owner !== null && $owner !== $userId) {
            return;
        }
        $this->sendCode(Secret::PHONE_ADD, $e164, $userId);
    }

    /**
     * Attaches the number once its code is confirmed by the user who asked for it.
     *
     * @throws PasswordlessException
     */
    public function confirm(string $userId, string $phone, #[SensitiveParameter] string $code): string
    {
        $e164 = self::normalize($phone);
        $secret = $this->secrets->spendCode(Secret::PHONE_ADD, $e164, $code);
        if ($secret === null || $secret->userId !== $userId) {
            throw PasswordlessException::codeInvalid();
        }
        $this->phones->attach($userId, $e164);

        return $e164;
    }

    private function sendCode(string $kind, string $e164, string $userId): void
    {
        $code = SecretStore::code($this->settings->otpLength);
        $this->secrets->issueCode($kind, $e164, $userId, $code, $this->settings->otpTtl);
        $this->sender->send(Message::SMS, $e164, 'sms.otp', ['code' => $code, 'ttl' => $this->settings->otpTtl], essential: true);
    }
}

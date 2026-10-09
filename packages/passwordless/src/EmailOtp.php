<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use Polaris\Contract\PasswordHasherInterface;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\PasswordChanged;
use Polaris\Event\UserEmailVerified;
use Polaris\Identity\EmailNormalizer;
use Polaris\Identity\PasswordPolicy;
use Polaris\Identity\SessionService;
use Polaris\Messaging\Message;
use Polaris\Messaging\Sender;
use Polaris\Model\RefreshToken;
use Polaris\Model\User;
use Polaris\Passwordless\Model\Secret;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;

/**
 * Email one-time codes for three purposes: signing in, verifying the email, resetting the password (the
 * code alternatives to core's link flows, which stay as they are). A code is bound to its purpose and
 * its address.
 */
final class EmailOtp
{
    public const string AMR = 'email_otp';
    public const string SIGN_IN = 'sign-in';
    public const string VERIFY_EMAIL = 'verify-email';
    public const string RESET_PASSWORD = 'reset-password';
    public const array PURPOSES = [self::SIGN_IN => Secret::EMAIL_SIGN_IN, self::VERIFY_EMAIL => Secret::EMAIL_VERIFY, self::RESET_PASSWORD => Secret::EMAIL_RESET];

    public function __construct(
        private readonly Settings $settings,
        private readonly SecretStore $secrets,
        private readonly Sessions $sessions,
        private readonly Sender $sender,
        private readonly UserRepository $users,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly PasswordPolicy $passwordPolicy,
        private readonly PasswordHasherInterface $hasher,
        private readonly SessionService $sessionService,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * Sends a code when the purpose applies to the address (an active user, or nobody and sign-up on, to
     * sign in; an unverified user to verify; an active user to reset); the caller answers the same
     * either way.
     */
    public function send(string $email, string $purpose): void
    {
        $email = EmailNormalizer::normalize($email);
        $user = $this->users->findOneBy(['email' => $email]);
        $active = $user instanceof User && $user->status !== User::STATUS_DISABLED;
        $applies = match ($purpose) {
            self::SIGN_IN => $active || (!$user instanceof User && $this->settings->signUp),
            self::VERIFY_EMAIL => $active && $user->emailVerifiedAt === null,
            default => $active,
        };
        if (!$applies) {
            return;
        }
        $code = SecretStore::code($this->settings->otpLength);
        $this->secrets->issueCode(self::PURPOSES[$purpose], $email, $user?->id, $code, $this->settings->otpTtl);
        $this->sender->send(Message::EMAIL, $email, 'email.otp', ['code' => $code, 'ttl' => $this->settings->otpTtl], essential: true);
    }

    /**
     * @return array<string, mixed> the envelope's `data`
     * @throws PasswordlessException
     */
    public function signIn(string $email, #[SensitiveParameter] string $code, ClientContext $client): array
    {
        $email = EmailNormalizer::normalize($email);
        if ($this->secrets->spendCode(Secret::EMAIL_SIGN_IN, $email, $code) === null) {
            throw PasswordlessException::codeInvalid();
        }

        return $this->sessions->open($this->sessions->forEmail($email), [self::AMR], $client);
    }

    /**
     * @throws PasswordlessException
     */
    public function verifyEmail(string $email, #[SensitiveParameter] string $code): void
    {
        $user = $this->spendFor(Secret::EMAIL_VERIFY, $email, $code);
        if ($user->emailVerifiedAt !== null) {
            return;
        }
        $now = $this->clock->now();
        $user->emailVerifiedAt = $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->events->dispatch(new UserEmailVerified($user->id, $user->email));
    }

    /**
     * Sets a new password and ends every session, as core's reset does.
     *
     * @throws PasswordlessException the password fails the policy (the code is kept), or the code is invalid
     */
    public function resetPassword(string $email, #[SensitiveParameter] string $code, #[SensitiveParameter] string $password): void
    {
        $violations = $this->passwordPolicy->validate($password);
        if ($violations !== []) {
            throw new PasswordlessException(PasswordlessException::PASSWORD_INVALID, $violations[0], $violations);
        }
        $user = $this->spendFor(Secret::EMAIL_RESET, $email, $code);
        $now = $this->clock->now();
        $user->passwordHash = $this->hasher->hash($password);
        $user->failedLoginCount = 0;
        $user->failedLoginAt = null;
        $user->lockedUntil = null;
        if ($user->status === User::STATUS_LOCKED) {
            $user->status = User::STATUS_ACTIVE;
        }
        $user->emailVerifiedAt ??= $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->sessionService->revokeAll($user->id, RefreshToken::REASON_PASSWORD_CHANGE);
        $this->events->dispatch(new PasswordChanged($user->id, PasswordChanged::METHOD_RESET));
    }

    /**
     * @throws PasswordlessException
     */
    private function spendFor(string $kind, string $email, string $code): User
    {
        $email = EmailNormalizer::normalize($email);
        $secret = $this->secrets->spendCode($kind, $email, $code);
        $user = $secret?->userId === null ? null : $this->sessions->active($secret->userId);
        if (!$user instanceof User || $user->status === User::STATUS_DISABLED) {
            throw PasswordlessException::codeInvalid();
        }

        return $user;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\UserEmailVerified;
use Polaris\Event\UserLoggedIn;
use Polaris\Identity\EmailNormalizer;
use Polaris\Identity\MfaFactorView;
use Polaris\Identity\MfaLoginService;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\SessionPrincipalResolverInterface;
use Polaris\Token\TokenService;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\Uid\Uuid;

use function array_map;
use function hash;
use function is_array;

/**
 * What every method ends with: the account behind a proven email (created when sign-up is on, verified
 * because the mailbox was proven), core's MFA gate, then a session opened as core opens one, answered as
 * core's login envelope; and the one-minute hand-off code a magic link redirects with.
 */
final class Sessions
{
    private const int CODE_TTL = 60;

    public function __construct(
        private readonly Settings $settings,
        private readonly UserRepository $users,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly TokenService $tokens,
        private readonly SessionPrincipalResolverInterface $principals,
        private readonly MfaLoginService $mfaLogin,
        private readonly CacheInterface $cache,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * The user who owns the email, created verified when sign-up is on; an unverified owner becomes
     * verified (the mailbox was just proven) and loses a password nobody proved the mailbox for.
     *
     * @throws PasswordlessException nobody owns it and sign-up is off
     */
    public function forEmail(string $email): User
    {
        $email = EmailNormalizer::normalize($email);
        $user = $this->users->findOneBy(['email' => $email]);
        $now = $this->clock->now();
        if (!$user instanceof User) {
            if (!$this->settings->signUp) {
                throw PasswordlessException::codeInvalid();
            }
            $user = new User();
            $user->id = Uuid::v7()->toRfc4122();
            $user->email = $email;
            $user->emailVerifiedAt = $now;
            $user->createdAt = $now;
            $user->updatedAt = $now;
            $this->unitOfWork->persist($user);
            $this->unitOfWork->flush();

            return $user;
        }
        if ($user->emailVerifiedAt === null) {
            // Whoever registered the address never proved it: a password they set is not the mailbox
            // owner's, so it goes (the owner can set one by reset), or it would outlive this sign-in.
            $user->emailVerifiedAt = $now;
            $user->passwordHash = null;
            $user->failedLoginCount = 0;
            $user->failedLoginAt = null;
            $user->lockedUntil = null;
            $user->updatedAt = $now;
            $this->unitOfWork->persist($user);
            $this->unitOfWork->flush();
            $this->events->dispatch(new UserEmailVerified($user->id, $user->email));
        }

        return $user;
    }

    /**
     * Opens a session for a user who just proved a factor: core's `mfa_required` envelope when the user
     * has a confirmed MFA factor and the gate applies, the login envelope otherwise.
     *
     * @param list<string> $amr
     * @return array<string, mixed> the envelope's `data`
     * @throws PasswordlessException the account is disabled
     */
    public function open(User $user, array $amr, ClientContext $client, bool $gate = true, ?string $organizationId = null, bool $mfa = false, ?int $authTime = null): array
    {
        if ($user->status === User::STATUS_DISABLED) {
            throw new PasswordlessException(PasswordlessException::ACCOUNT_DISABLED, 'This account is disabled.');
        }
        if ($gate && $this->settings->respectMfa) {
            $factors = $this->mfaLogin->confirmedFactors($user->id);
            if ($factors !== []) {
                $challenge = $this->mfaLogin->beginChallenge($user->id, $factors);

                return [
                    'mfa_required' => true,
                    'mfa_token' => $challenge->mfaToken,
                    'factors' => array_map(static fn(MfaFactorView $factor): array => $factor->toArray(), $challenge->factors),
                ];
            }
        }
        $now = $this->clock->now();
        $resolved = $this->principals->resolve($user->id, $organizationId);
        $principal = new SessionPrincipal($user->id, $organizationId, $resolved->roles, $resolved->scope, $user->emailVerifiedAt !== null, $mfa, $amr, $authTime ?? $now->getTimestamp());
        $user->lastLoginAt = $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $tokens = $this->tokens->issue($principal, $client);
        $this->events->dispatch(new UserLoggedIn($user->id, $tokens->sessionId, $client->ip, $client->userAgent, $amr));

        return [
            'access_token' => $tokens->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $tokens->accessExpiresIn,
            'refresh_token' => $tokens->refreshToken,
            'user' => ['id' => $user->id, 'email' => $user->email, 'email_verified' => $user->emailVerifiedAt !== null],
        ];
    }

    /**
     * Keeps an envelope behind a one-minute, one-use code; the code.
     *
     * @param array<string, mixed> $envelope
     */
    public function handOff(array $envelope): string
    {
        $code = SecretStore::token();
        $this->cache->set(self::key($code), $envelope, self::CODE_TTL);

        return $code;
    }

    /**
     * The envelope a hand-off code stands for, once.
     *
     * @return array<string, mixed>
     * @throws PasswordlessException the code is unknown, used or expired
     */
    public function exchange(string $code): array
    {
        $key = self::key($code);
        $envelope = $this->cache->get($key);
        $this->cache->delete($key);
        if (!is_array($envelope)) {
            throw PasswordlessException::tokenInvalid();
        }

        return $envelope;
    }

    public function active(string $userId): ?User
    {
        $user = $this->users->find($userId);

        return $user instanceof User ? $user : null;
    }

    private static function key(string $code): string
    {
        return 'polaris.passwordless.code.' . hash('sha256', $code);
    }
}

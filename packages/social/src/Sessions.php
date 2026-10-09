<?php

declare(strict_types=1);

namespace Polaris\Social;

use Polaris\Config\AuthConfig;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\UserLoggedIn;
use Polaris\Identity\EmailNormalizer;
use Polaris\Identity\MfaFactorView;
use Polaris\Identity\MfaLoginService;
use Polaris\Identity\SessionService;
use Polaris\Model\RefreshToken;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\SessionPrincipalResolverInterface;
use Polaris\Token\TokenService;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

use function array_map;

/**
 * What a social sign-in ends with: core's MFA gate when it applies, then a session opened as core opens
 * one (`amr: ["social:<provider>"]`), answered as core's login envelope; and the user a sign-up creates.
 */
final class Sessions
{
    public function __construct(
        private readonly Settings $settings,
        private readonly AuthConfig $auth,
        private readonly UserRepository $users,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly SessionService $sessionService,
        private readonly TokenService $tokens,
        private readonly SessionPrincipalResolverInterface $principals,
        private readonly MfaLoginService $mfaLogin,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
    }

    public function byEmail(string $email): ?User
    {
        $user = $this->users->findOneBy(['email' => EmailNormalizer::normalize($email)]);

        return $user instanceof User ? $user : null;
    }

    public function find(string $userId): ?User
    {
        $user = $this->users->find($userId);

        return $user instanceof User ? $user : null;
    }

    /**
     * A user without a password, verified when the provider vouched for the address.
     */
    public function create(string $email, bool $verified, ?string $name): User
    {
        $now = $this->clock->now();
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = EmailNormalizer::normalize($email);
        $user->displayName = $name;
        $user->emailVerifiedAt = $verified ? $now : null;
        $user->createdAt = $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();

        return $user;
    }

    /**
     * A trusted provider just proved the mailbox of a user nobody had proved it for: whoever registered
     * the address did not own it, so the password, the sessions and the other linked accounts go, as a
     * passwordless sign-in does for the password; the user becomes verified.
     */
    public function claim(User $user): void
    {
        $now = $this->clock->now();
        $user->emailVerifiedAt = $now;
        $user->passwordHash = null;
        $user->failedLoginCount = 0;
        $user->failedLoginAt = null;
        $user->lockedUntil = null;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->sessionService->revokeAll($user->id, RefreshToken::REASON_ADMIN);
    }

    /**
     * @return array<string, mixed> the envelope's `data`
     * @throws SocialException the account is disabled, or unverified where core requires verification
     */
    public function open(User $user, string $provider, ClientContext $client): array
    {
        if ($user->status === User::STATUS_DISABLED) {
            throw new SocialException(SocialException::ACCOUNT_DISABLED, 'This account is disabled.');
        }
        if ($this->auth->requireVerifiedEmail && $user->emailVerifiedAt === null) {
            throw new SocialException(SocialException::EMAIL_UNVERIFIED, 'Verify your email address before signing in: the provider did not vouch for it.');
        }
        if ($this->settings->respectMfa) {
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
        $amr = ['social:' . $provider];
        $now = $this->clock->now();
        $resolved = $this->principals->resolve($user->id, null);
        $principal = new SessionPrincipal($user->id, null, $resolved->roles, $resolved->scope, $user->emailVerifiedAt !== null, false, $amr, $now->getTimestamp());
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
}

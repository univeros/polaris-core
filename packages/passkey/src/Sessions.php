<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use Polaris\Config\AuthConfig;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\UserLoggedIn;
use Polaris\Identity\MfaFactorView;
use Polaris\Identity\MfaLoginService;
use Polaris\Model\MfaFactor;
use Polaris\Model\User;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\SessionPrincipalResolverInterface;
use Polaris\Token\TokenService;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

use function array_filter;
use function array_map;
use function array_values;

/**
 * What a passkey sign-in ends with: core's MFA gate when it applies (a passkey without user
 * verification is one factor), then a session opened as core opens one, answered as core's login
 * envelope.
 */
final class Sessions
{
    public const string AMR = 'passkey';

    public function __construct(
        private readonly AuthConfig $auth,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly TokenService $tokens,
        private readonly SessionPrincipalResolverInterface $principals,
        private readonly MfaLoginService $mfaLogin,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param string|null $usedFactorId the factor the signing passkey backs: it cannot be its own second factor
     * @return array<string, mixed> the envelope's `data`
     * @throws PasskeyException the account is disabled, unverified where core requires it, or has no other factor
     */
    public function open(User $user, ClientContext $client, bool $userVerified, ?string $usedFactorId = null): array
    {
        if ($user->status === User::STATUS_DISABLED) {
            throw new PasskeyException(PasskeyException::ACCOUNT_DISABLED, 'This account is disabled.');
        }
        if ($this->auth->requireVerifiedEmail && $user->emailVerifiedAt === null) {
            throw new PasskeyException(PasskeyException::EMAIL_UNVERIFIED, 'Verify your email address before signing in.');
        }
        if (!$userVerified) {
            $all = $this->mfaLogin->confirmedFactors($user->id);
            $factors = array_values(array_filter($all, static fn(MfaFactor $factor): bool => $factor->id !== $usedFactorId));
            if ($all !== [] && $factors === []) {
                throw new PasskeyException(PasskeyException::USER_VERIFICATION_REQUIRED, 'This passkey is the account\'s only second factor: the authenticator must verify the user (a PIN, a fingerprint, a face).');
            }
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
        $resolved = $this->principals->resolve($user->id, null);
        $principal = new SessionPrincipal($user->id, null, $resolved->roles, $resolved->scope, $user->emailVerifiedAt !== null, $userVerified, [self::AMR], $now->getTimestamp());
        $user->lastLoginAt = $now;
        $user->updatedAt = $now;
        $this->unitOfWork->persist($user);
        $tokens = $this->tokens->issue($principal, $client);
        $this->events->dispatch(new UserLoggedIn($user->id, $tokens->sessionId, $client->ip, $client->userAgent, [self::AMR]));

        return [
            'access_token' => $tokens->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $tokens->accessExpiresIn,
            'refresh_token' => $tokens->refreshToken,
            'user' => ['id' => $user->id, 'email' => $user->email, 'email_verified' => $user->emailVerifiedAt !== null],
        ];
    }
}

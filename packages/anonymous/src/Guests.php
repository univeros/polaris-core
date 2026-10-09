<?php

declare(strict_types=1);

namespace Polaris\Anonymous;

use Closure;
use DateInterval;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\UserDeleted;
use Polaris\Event\UserLoggedIn;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Identity\SessionService;
use Polaris\Model\RefreshToken;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\TokenService;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Uid\Uuid;
use Throwable;

use function is_string;

/**
 * The guests: a sign-in that creates a core user with a placeholder email and no password, the
 * conversion into the account the guest signed into or up (the host moves its data in `onConvert`),
 * and the pruning of the guests nobody converted.
 */
final class Guests
{
    public const string AMR = 'anonymous';
    public const string EMAIL_DOMAIN = 'anonymous.invalid';
    public const string SYSTEM = 'system';

    /** Core's rows keyed by the user, deleted with a pruned guest. */
    private const array USER_TABLES = ['auth_refresh_tokens', 'auth_mfa_factors', 'auth_otp_challenges', 'auth_recovery_codes', 'auth_email_verifications', 'auth_password_resets'];

    /**
     * @param (Closure(string, string): void)|null $onConvert the host's hook: guest id, account id
     */
    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly UserRepository $users,
        private readonly TokenService $tokens,
        private readonly SessionService $sessions,
        private readonly TokenFactoryInterface $tokenFactory,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
        private readonly ?Closure $onConvert,
        private readonly int $pruneAfterDays,
    ) {
    }

    /**
     * A new guest and its session, as core's login envelope.
     *
     * @return array<string, mixed>
     */
    public function signIn(ClientContext $client): array
    {
        $now = $this->clock->now();
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $user->id . '@' . self::EMAIL_DOMAIN;
        $user->createdAt = $now;
        $user->updatedAt = $now;
        $user->lastLoginAt = $now;
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->database->insert(Schema::GUESTS, ['user_id' => $user->id, 'created_at' => $now, 'converted_at' => null, 'converted_user_id' => null]);
        $tokens = $this->tokens->issue(new SessionPrincipal($user->id, amr: [self::AMR], authTime: $now->getTimestamp()), $client);
        $this->events->dispatch(new UserLoggedIn($user->id, $tokens->sessionId, $client->ip, $client->userAgent, [self::AMR]));

        return [
            'access_token' => $tokens->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $tokens->accessExpiresIn,
            'refresh_token' => $tokens->refreshToken,
            'user' => ['id' => $user->id, 'email' => $user->email, 'email_verified' => false],
        ];
    }

    public function isGuest(string $userId): bool
    {
        return $this->database->findOne(Schema::GUESTS, ['user_id' => $userId]) !== null;
    }

    /**
     * Converts the guest into the account whose access token the caller holds. The guest row is claimed
     * first, so two concurrent conversions cannot both run the hook; the host's hook runs next (a failing
     * hook releases the claim and converts nothing); then the guest's sessions end and the guest is
     * disabled. Its id stays for the host's data.
     *
     * @return array{guest_id: string, user_id: string}
     * @throws AnonymousException
     */
    public function convert(string $guestId, #[SensitiveParameter] string $accessToken): array
    {
        $guest = $this->database->findOne(Schema::GUESTS, ['user_id' => $guestId]);
        if ($guest === null || $guest['converted_at'] !== null) {
            throw new AnonymousException(AnonymousException::NOT_A_GUEST);
        }
        $userId = $this->liveSubject($accessToken);
        if ($userId === null || $userId === $guestId || $this->isGuest($userId)) {
            throw new AnonymousException(AnonymousException::TOKEN_INVALID);
        }
        $now = $this->clock->now();
        if ($this->database->update(Schema::GUESTS, ['user_id' => $guestId, 'converted_at' => null], ['converted_at' => $now, 'converted_user_id' => $userId]) !== 1) {
            throw new AnonymousException(AnonymousException::NOT_A_GUEST);
        }
        try {
            if ($this->onConvert !== null) {
                ($this->onConvert)($guestId, $userId);
            }
        } catch (Throwable $exception) {
            $this->database->update(Schema::GUESTS, ['user_id' => $guestId], ['converted_at' => null, 'converted_user_id' => null]);

            throw $exception;
        }
        $this->sessions->revokeAll($guestId, RefreshToken::REASON_LOGOUT);
        $user = $this->users->find($guestId);
        if ($user instanceof User) {
            $user->status = User::STATUS_DISABLED;
            $user->updatedAt = $now;
            $this->unitOfWork->persist($user);
            $this->unitOfWork->flush();
        }

        return ['guest_id' => $guestId, 'user_id' => $userId];
    }

    /**
     * Deletes the unconverted guests older than the policy with their core rows; how many.
     */
    public function prune(): int
    {
        $before = $this->clock->now()->sub(new DateInterval('P' . $this->pruneAfterDays . 'D'));
        $pruned = 0;
        foreach ($this->database->findMany(Schema::GUESTS, ['converted_at' => null, 'created_at' => Condition::lt($before)]) as $row) {
            $guestId = (string) $row['user_id'];
            $this->database->transaction(function () use ($guestId): void {
                foreach (self::USER_TABLES as $table) {
                    $this->database->delete($table, ['user_id' => $guestId]);
                }
                $this->database->delete('auth_users', ['id' => $guestId]);
                $this->database->delete(Schema::GUESTS, ['user_id' => $guestId]);
            });
            $this->events->dispatch(new UserDeleted($guestId, self::SYSTEM));
            ++$pruned;
        }

        return $pruned;
    }

    /**
     * The subject of a valid access token whose session is still live.
     */
    private function liveSubject(string $accessToken): ?string
    {
        try {
            $token = $this->tokenFactory->fromTokenString($accessToken);
        } catch (AuthorizationTokenException) {
            return null;
        }
        $subject = $token->getMetadata('sub');
        $sessionId = $token->getMetadata('sid');
        if (!is_string($subject) || $subject === '' || !is_string($sessionId) || $sessionId === '') {
            return null;
        }
        $live = $this->database->findOne('auth_refresh_tokens', ['family_id' => $sessionId, 'user_id' => $subject, 'revoked_at' => null]);

        return $live === null ? null : $subject;
    }
}

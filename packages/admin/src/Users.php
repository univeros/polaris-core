<?php

declare(strict_types=1);

namespace Polaris\Admin;

use Polaris\Audit\Activity\ActivityTracker;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\PasswordHasherInterface;
use Polaris\Contract\UnitOfWorkInterface;
use Polaris\Event\PasswordChanged;
use Polaris\Exception\UserNotFoundException;
use Polaris\Identity\PasswordPolicy;
use Polaris\Identity\SessionService;
use Polaris\Identity\UserAdminService;
use Polaris\Model\RefreshToken;
use Polaris\Model\User;
use Polaris\Repository\RowMapper;
use Polaris\Repository\UserRepository;
use Polaris\Schema\Schema as Registry;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;

use function array_slice;
use function count;
use function in_array;

use const DATE_ATOM;

/**
 * The operator's view of the users: a filtered, cursor-paginated list, one user with their activity,
 * ban and unban (core's disable and enable), set a password, delete (core's anonymisation).
 */
final class Users
{
    public const int DEFAULT_LIMIT = 50;
    public const int MAX_LIMIT = 200;
    public const array STATUSES = [User::STATUS_ACTIVE, User::STATUS_DISABLED, User::STATUS_LOCKED];

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly UserRepository $users,
        private readonly UserAdminService $admin,
        private readonly PasswordHasherInterface $hasher,
        private readonly PasswordPolicy $policy,
        private readonly SessionService $sessions,
        private readonly UnitOfWorkInterface $unitOfWork,
        private readonly ActivityTracker $activity,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Oldest first (ids are UUID v7), `cursor` the last id of the previous page.
     *
     * @return array{data: list<array<string, mixed>>, next_cursor: string|null}
     */
    public function list(?string $email = null, ?string $status = null, ?string $cursor = null, int $limit = self::DEFAULT_LIMIT): array
    {
        $limit = max(1, min(self::MAX_LIMIT, $limit));
        $criteria = [];
        if ($email !== null) {
            $criteria['email'] = $email;
        }
        if ($status !== null) {
            $criteria['status'] = $status;
        }
        if ($cursor !== null) {
            $criteria['id'] = Condition::gt($cursor);
        }
        $model = Registry::for(User::class);
        $rows = $this->database->findMany($model->table, $criteria, ['id' => 'asc'], $limit + 1);
        $data = [];
        foreach (array_slice($rows, 0, $limit) as $row) {
            /** @var User $user */
            $user = RowMapper::hydrate($model, $row);
            $data[] = $this->shape($user);
        }

        return ['data' => $data, 'next_cursor' => count($rows) > $limit && $data !== [] ? $data[count($data) - 1]['id'] : null];
    }

    public function find(string $id): ?User
    {
        return $this->users->find($id);
    }

    /**
     * @return array<string, mixed>
     */
    public function shape(User $user): array
    {
        return [
            'id' => $user->id,
            'email' => $user->email,
            'display_name' => $user->displayName,
            'status' => $user->status,
            'email_verified' => $user->emailVerifiedAt !== null,
            'mfa_enforced' => $user->mfaEnforced,
            'locked_until' => $user->lockedUntil?->format(DATE_ATOM),
            'created_at' => $user->createdAt->format(DATE_ATOM),
            'last_login_at' => $user->lastLoginAt?->format(DATE_ATOM),
            'last_active_at' => $this->activity->lastActiveAt($user->id)?->format(DATE_ATOM),
        ];
    }

    /**
     * @throws \LogicException banning yourself
     * @throws UserNotFoundException
     */
    public function ban(string $actorId, string $userId): void
    {
        $this->admin->disable($actorId, $userId);
    }

    /**
     * @throws \LogicException an anonymised account
     * @throws UserNotFoundException
     */
    public function unban(string $actorId, string $userId): void
    {
        $this->admin->enable($actorId, $userId);
    }

    /**
     * Sets a new password (the policy applies) and ends every session, as a password reset does.
     *
     * @return list<string> the policy's violations; empty when the password was set
     *
     * @throws UserNotFoundException
     */
    public function setPassword(string $userId, #[SensitiveParameter] string $password): array
    {
        $user = $this->users->find($userId) ?? throw new UserNotFoundException('The user does not exist.');
        $violations = $this->policy->validate($password);
        if ($violations !== []) {
            return $violations;
        }
        $user->passwordHash = $this->hasher->hash($password);
        $user->updatedAt = $this->clock->now();
        $this->unitOfWork->persist($user);
        $this->unitOfWork->flush();
        $this->sessions->revokeAll($userId, RefreshToken::REASON_PASSWORD_CHANGE);
        $this->events->dispatch(new PasswordChanged($userId, PasswordChanged::METHOD_RESET));

        return [];
    }

    /**
     * @throws UserNotFoundException
     */
    public function delete(string $actorId, string $userId): void
    {
        $this->admin->anonymize($actorId, $userId);
    }

    public static function isStatus(string $status): bool
    {
        return in_array($status, self::STATUSES, true);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Tests\AdapterConformance;

use DateTimeImmutable;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Increment;
use Polaris\Model\OtpChallenge;
use Polaris\Model\Permission;
use Polaris\Model\RefreshToken;
use Polaris\Model\Role;
use Polaris\Model\RolePermission;
use Polaris\Model\User;
use Polaris\Repository\IdentityMap;
use Polaris\Repository\OtpChallengeRepository;
use Polaris\Repository\RefreshTokenRepository;
use Polaris\Repository\RolePermissionRepository;
use Polaris\Repository\UnitOfWork;
use Polaris\Repository\UserRepository;
use RuntimeException;
use Symfony\Component\Uid\Uuid;

use function str_repeat;

/**
 * The public adapter conformance suite: every repository operation and criteria form over one
 * {@see DatabaseAdapter}. Mix into a test case that provides {@see adapter()} against a schema
 * with the Polaris tables.
 */
trait AdapterConformanceTests
{
    abstract protected function adapter(): DatabaseAdapter;

    private function unitOfWork(): UnitOfWork
    {
        return new UnitOfWork($this->adapter(), new IdentityMap());
    }

    public function testPersistInsertsAndReadsBackTypedValues(): void
    {
        $unitOfWork = $this->unitOfWork();
        $users = new UserRepository($this->adapter(), $unitOfWork->identities());
        $now = new DateTimeImmutable('2026-06-07 10:00:00');
        $user = $this->user('ada@example.com', $now);
        $user->failedLoginCount = 2;
        $user->mfaEnforced = true;
        $user->failedLoginAt = $now;

        $unitOfWork->persist($user);
        $unitOfWork->flush();
        $unitOfWork->clear();

        $found = $users->findOneBy(['email' => 'ada@example.com']);
        self::assertInstanceOf(User::class, $found);
        self::assertNotSame($user, $found);
        self::assertSame($user->id, $found->id);
        self::assertSame('active', $found->status);
        self::assertTrue($found->mfaEnforced);
        self::assertSame(2, $found->failedLoginCount);
        self::assertNull($found->passwordHash);
        self::assertSame('2026-06-07 10:00:00', $found->failedLoginAt?->format('Y-m-d H:i:s'));
        self::assertSame($user->id, $users->find($user->id)?->id);
        self::assertCount(1, $users->findAll());
    }

    public function testIdentityMapReturnsOneInstancePerRowUntilCleared(): void
    {
        $unitOfWork = $this->unitOfWork();
        $users = new UserRepository($this->adapter(), $unitOfWork->identities());
        $user = $this->user('one@example.com', new DateTimeImmutable('2026-06-07 10:00:00'));
        $unitOfWork->persist($user);
        $unitOfWork->flush();

        self::assertSame($user, $users->find($user->id), 'the written object is the tracked one');
        self::assertSame($users->find($user->id), $users->findOneBy(['email' => 'one@example.com']));

        $unitOfWork->clear();
        self::assertNotSame($user, $users->find($user->id));
    }

    public function testFlushWritesOnlyChangedColumnsAndRemoveDeletes(): void
    {
        $unitOfWork = $this->unitOfWork();
        $users = new UserRepository($this->adapter(), $unitOfWork->identities());
        $user = $this->user('two@example.com', new DateTimeImmutable('2026-06-07 10:00:00'));
        $unitOfWork->persist($user);
        $unitOfWork->flush();

        $user->displayName = 'Two';
        $user->status = User::STATUS_LOCKED;
        $unitOfWork->persist($user);
        $unitOfWork->flush();
        $unitOfWork->clear();

        $reloaded = $users->find($user->id);
        self::assertInstanceOf(User::class, $reloaded);
        self::assertSame('Two', $reloaded->displayName);
        self::assertSame(User::STATUS_LOCKED, $reloaded->status);
        self::assertSame(1, $this->adapter()->count('auth_users', ['id' => $user->id]));

        $unitOfWork->remove($reloaded);
        $unitOfWork->flush();
        self::assertNull($users->find($user->id));
        self::assertSame(0, $this->adapter()->count('auth_users', []));
    }

    public function testCriteriaFormsEqualityInNullAndConditions(): void
    {
        $unitOfWork = $this->unitOfWork();
        $tokens = new RefreshTokenRepository($this->adapter(), $unitOfWork->identities());
        $now = new DateTimeImmutable('2026-06-07 10:00:00');
        $userId = Uuid::v7()->toRfc4122();
        $live = $this->refreshToken($userId, $now, 'a');
        $revoked = $this->refreshToken($userId, $now, 'b');
        $revoked->revokedAt = $now;
        $other = $this->refreshToken(Uuid::v7()->toRfc4122(), $now->modify('+1 hour'), 'c');
        foreach ([$live, $revoked, $other] as $token) {
            $unitOfWork->persist($token);
        }
        $unitOfWork->flush();
        $unitOfWork->clear();

        self::assertCount(2, $tokens->findBy(['userId' => $userId]));
        self::assertCount(1, $tokens->findBy(['userId' => $userId, 'revokedAt' => null]));
        self::assertCount(2, $tokens->findBy(['tokenHash' => [$live->tokenHash, $other->tokenHash]]));
        self::assertCount(1, $tokens->findBy(['revokedAt' => Condition::notNull()]));
        self::assertCount(2, $tokens->findBy(['createdAt' => Condition::lt($now->modify('+30 minutes'))]));
        self::assertCount(1, $tokens->findBy(['createdAt' => Condition::gte($now->modify('+30 minutes'))]));
        self::assertNull($tokens->findOneBy(['tokenHash' => 'missing']));
        $ordered = $this->adapter()->findMany('auth_refresh_tokens', ['user_id' => $userId], ['token_hash' => 'desc'], 1);
        self::assertSame($revoked->tokenHash, $ordered[0]['token_hash'] ?? null);
    }

    public function testConditionalUpdateWithIncrementIsAtomicCompareAndSwap(): void
    {
        $unitOfWork = $this->unitOfWork();
        $challenges = new OtpChallengeRepository($this->adapter(), $unitOfWork->identities());
        $challenge = new OtpChallenge();
        $challenge->id = Uuid::v7()->toRfc4122();
        $challenge->userId = Uuid::v7()->toRfc4122();
        $challenge->codeHash = str_repeat('c', 64);
        $challenge->maxAttempts = 2;
        $challenge->createdAt = new DateTimeImmutable('2026-06-07 10:00:00');
        $challenge->expiresAt = new DateTimeImmutable('2026-06-07 10:10:00');
        $unitOfWork->persist($challenge);
        $unitOfWork->flush();
        $unitOfWork->clear();

        $spend = fn(): int => $this->adapter()->update(
            'auth_otp_challenges',
            ['id' => $challenge->id, 'attempts' => Condition::lt($challenge->maxAttempts)],
            ['attempts' => new Increment()],
        );
        self::assertSame(1, $spend());
        self::assertSame(1, $spend());
        self::assertSame(0, $spend(), 'the budget is enforced by the database');
        self::assertSame(2, $challenges->find($challenge->id)?->attempts);

        $claim = fn(): int => $this->adapter()->update(
            'auth_otp_challenges',
            ['id' => $challenge->id, 'consumed_at' => null],
            ['consumed_at' => new DateTimeImmutable('2026-06-07 10:05:00')],
        );
        self::assertSame(1, $claim());
        self::assertSame(0, $claim(), 'a second consumer loses the race');
    }

    public function testTransactionRollsBackOnException(): void
    {
        $unitOfWork = $this->unitOfWork();
        $users = new UserRepository($this->adapter(), $unitOfWork->identities());
        $user = $this->user('rollback@example.com', new DateTimeImmutable('2026-06-07 10:00:00'));

        try {
            $this->adapter()->transaction(function () use ($unitOfWork, $user): void {
                $unitOfWork->persist($user);
                $unitOfWork->flush();
                throw new RuntimeException('abort');
            });
        } catch (RuntimeException) {
            // expected: the adapter must let the exception propagate after rolling back
        }
        $unitOfWork->clear();

        self::assertNull($users->find($user->id));
    }

    public function testCompositeKeyModelsRoundTrip(): void
    {
        $unitOfWork = $this->unitOfWork();
        $links = new RolePermissionRepository($this->adapter(), $unitOfWork->identities());
        $now = new DateTimeImmutable('2026-06-07 10:00:00');
        $role = new Role();
        $role->id = Uuid::v7()->toRfc4122();
        $role->name = 'Owner';
        $role->slug = 'owner';
        $role->createdAt = $now;
        $role->updatedAt = $now;
        $permission = new Permission();
        $permission->id = Uuid::v7()->toRfc4122();
        $permission->key = 'org.manage';
        $permission->description = 'Manage the organization';
        $link = new RolePermission();
        $link->roleId = $role->id;
        $link->permissionId = $permission->id;
        foreach ([$role, $permission, $link] as $object) {
            $unitOfWork->persist($object);
        }
        $unitOfWork->flush();
        $unitOfWork->clear();

        $found = $links->findBy(['roleId' => $link->roleId]);
        self::assertCount(1, $found);
        self::assertSame($link->permissionId, $found[0]->permissionId);

        $unitOfWork->remove($found[0]);
        $unitOfWork->flush();
        self::assertSame([], $links->findBy(['roleId' => $link->roleId]));
    }

    private function user(string $email, DateTimeImmutable $now): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->createdAt = $now;
        $user->updatedAt = $now;

        return $user;
    }

    private function refreshToken(string $userId, DateTimeImmutable $createdAt, string $suffix): RefreshToken
    {
        $token = new RefreshToken();
        $token->id = Uuid::v7()->toRfc4122();
        $token->userId = $userId;
        $token->familyId = Uuid::v7()->toRfc4122();
        $token->tokenHash = str_repeat($suffix, 64);
        $token->createdAt = $createdAt;
        $token->expiresAt = $createdAt->modify('+30 days');

        return $token;
    }
}

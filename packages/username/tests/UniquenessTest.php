<?php

declare(strict_types=1);

namespace Polaris\Username\Tests;

use DateTimeImmutable;
use Override;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Polaris\Schema\Schema as CoreSchema;
use Polaris\Tests\Persistence\DatabaseTestCase;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Username\Rules;
use Polaris\Username\Schema;
use Polaris\Username\Tests\Support\RacingAdapter;
use Polaris\Username\UsernameException;
use Polaris\Username\Usernames;
use Throwable;

/**
 * Case-insensitive uniqueness on a real database: SQLite by default, PostgreSQL or MySQL with
 * `DB_CONNECTION` (CI runs PostgreSQL). The lowercased column and its unique index hold without
 * collations, including when another user takes the name between the lookup and the write.
 */
#[CoversClass(Usernames::class)]
#[CoversClass(Rules::class)]
#[RunTestsInSeparateProcesses]
final class UniquenessTest extends DatabaseTestCase
{
    #[Override]
    protected function setUp(): void
    {
        CoreSchema::register(...Schema::models());
        parent::setUp();
        foreach (['u1', 'u2', 'u3'] as $id) {
            $this->adapter->insert('auth_users', ['id' => $id, 'email' => $id . '@example.com', 'status' => 'active', 'mfa_enforced' => false, 'failed_login_count' => 0, 'created_at' => new DateTimeImmutable(), 'updated_at' => new DateTimeImmutable()]);
        }
    }

    public function testAUsernameIsUniqueWithoutRegardToCase(): void
    {
        $usernames = new Usernames($this->adapter, new FrozenClock(new DateTimeImmutable('2026-10-09T10:00:00+00:00')), new Rules());

        $ada = $usernames->set('u1', 'Ada.Lovelace');
        self::assertSame(['ada.lovelace', 'Ada.Lovelace'], [$ada->username, $ada->displayUsername]);
        self::assertSame('u1', $usernames->userId('ADA.LOVELACE'));
        self::assertSame('u1', $usernames->userId(' ada.lovelace '));
        foreach (['ada.lovelace', 'ADA.LOVELACE', 'aDa.LoVeLaCe'] as $taken) {
            try {
                $usernames->set('u2', $taken);
                self::fail($taken . ' is taken');
            } catch (UsernameException $exception) {
                self::assertSame(UsernameException::TAKEN, $exception->reason, $taken);
            }
        }
        self::assertSame('ADA.lovelace', $usernames->set('u1', 'ADA.lovelace')->displayUsername, 'the owner changes the case');

        try {
            $this->adapter->insert(Schema::USERNAMES, ['user_id' => 'u3', 'username' => 'ada.lovelace', 'display_username' => 'ADA.LOVELACE', 'created_at' => new DateTimeImmutable(), 'updated_at' => new DateTimeImmutable()]);
            self::fail('the unique index refuses a second row for the same lowercased name');
        } catch (Throwable) {
            self::addToAssertionCount(1);
        }
    }

    public function testTheUniqueIndexDecidesARaceBetweenTheLookupAndTheWrite(): void
    {
        $racing = new RacingAdapter($this->adapter);
        $usernames = new Usernames($racing, new FrozenClock(new DateTimeImmutable('2026-10-09T10:00:00+00:00')), new Rules());

        try {
            $usernames->set('u2', 'Grace');
            self::fail('the other writer won');
        } catch (UsernameException $exception) {
            self::assertSame(UsernameException::TAKEN, $exception->reason);
        }
        self::assertSame('u1', $usernames->userId('grace'));
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Tests\Pdo;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\Dialect;
use Polaris\Model\User;
use Polaris\Pdo\SqlSchema;
use Polaris\Schema\Schema;

use function array_filter;
use function count;
use function implode;
use function str_contains;

#[CoversClass(SqlSchema::class)]
final class SqlSchemaTest extends TestCase
{
    public function testCreatesAndDropsEveryTableOnSqlite(): void
    {
        $pdo = new PDO('sqlite::memory:');
        foreach (SqlSchema::createAll(Dialect::Sqlite) as $statement) {
            $pdo->exec($statement);
        }
        self::assertSame(count(Schema::all()), $this->tableCount($pdo));

        foreach (SqlSchema::dropAll(Dialect::Sqlite) as $statement) {
            $pdo->exec($statement);
        }
        self::assertSame(0, $this->tableCount($pdo));
    }

    public function testReferencedTablesComeFirstAndKeysAreDeclared(): void
    {
        $sql = implode("\n", SqlSchema::createAll(Dialect::Postgres));

        self::assertLessThan(strpos($sql, 'CREATE TABLE "auth_role_permissions"'), strpos($sql, 'CREATE TABLE "auth_roles"'));
        self::assertLessThan(strpos($sql, 'CREATE TABLE "auth_role_permissions"'), strpos($sql, 'CREATE TABLE "auth_permissions"'));
        self::assertStringContainsString('PRIMARY KEY ("role_id", "permission_id")', $sql);
        self::assertStringContainsString('FOREIGN KEY ("role_id") REFERENCES "auth_roles" ("id") ON DELETE CASCADE ON UPDATE CASCADE', $sql);
        self::assertStringContainsString('CREATE UNIQUE INDEX "auth_users_email_unique" ON "auth_users" ("email")', $sql);
    }

    public function testTypesFollowTheDialect(): void
    {
        $users = Schema::for(User::class);
        $postgres = implode("\n", SqlSchema::create($users, Dialect::Postgres));
        $mysql = implode("\n", SqlSchema::create($users, Dialect::Mysql));
        $sqlite = implode("\n", SqlSchema::create($users, Dialect::Sqlite));

        self::assertStringContainsString('"email" VARCHAR(320) NOT NULL', $postgres);
        self::assertStringContainsString('"mfa_enforced" BOOLEAN NOT NULL DEFAULT FALSE', $postgres);
        self::assertStringContainsString('"created_at" TIMESTAMP NOT NULL', $postgres);
        self::assertStringContainsString('`mfa_enforced` TINYINT(1) NOT NULL DEFAULT 0', $mysql);
        self::assertStringContainsString('`created_at` DATETIME NOT NULL', $mysql);
        self::assertStringContainsString('"status" VARCHAR(16) NOT NULL DEFAULT \'active\'', $sqlite);
        self::assertStringContainsString('"email_verified_at" DATETIME NULL', $sqlite);
    }

    private function tableCount(PDO $pdo): int
    {
        $names = $pdo->query("SELECT name FROM sqlite_master WHERE type = 'table'")->fetchAll(PDO::FETCH_COLUMN);

        return count(array_filter($names, static fn(string $name): bool => str_contains($name, 'auth_')));
    }
}

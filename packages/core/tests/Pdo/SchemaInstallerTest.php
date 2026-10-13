<?php

declare(strict_types=1);

namespace Polaris\Tests\Pdo;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\Dialect;
use Polaris\Pdo\PdoAdapter;
use Polaris\Pdo\SchemaDiff;
use Polaris\Pdo\SchemaInspector;
use Polaris\Pdo\SchemaInstaller;

#[CoversClass(SchemaInstaller::class)]
final class SchemaInstallerTest extends TestCase
{
    public function testCreatesSeedsAndDrops(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->exec('PRAGMA foreign_keys = ON');

        SchemaInstaller::create($pdo);
        self::assertSame([], (new SchemaDiff(new SchemaInspector($pdo, Dialect::Sqlite), Dialect::Sqlite))->run());
        self::assertGreaterThan(0, (int) $pdo->query('SELECT COUNT(*) FROM auth_permissions')->fetchColumn());
        self::assertGreaterThan(0, (int) $pdo->query('SELECT COUNT(*) FROM auth_roles WHERE organization_id IS NULL')->fetchColumn());

        SchemaInstaller::drop($pdo);
        self::assertSame(0, (int) $pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth_%'")->fetchColumn());
    }

    public function testCreatesOnlyTheMissingTablesInForeignKeyOrderAndLeavesTheOthersAlone(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->exec('PRAGMA foreign_keys = ON');
        SchemaInstaller::create($pdo);
        $pdo->exec("INSERT INTO auth_users (id, email, created_at, updated_at) VALUES ('u1', 'ada@example.com', '2026-10-13 10:00:00', '2026-10-13 10:00:00')");
        $pdo->exec('DROP TABLE auth_membership_roles');
        $pdo->exec('DROP TABLE auth_memberships');

        $created = SchemaInstaller::createMissing($pdo);

        self::assertSame(['auth_memberships', 'auth_membership_roles'], $created, 'only the missing tables, a referenced one before the one that references it');
        self::assertSame(1, (int) $pdo->query('SELECT COUNT(*) FROM auth_users')->fetchColumn(), 'its rows too');
        self::assertSame([], (new SchemaDiff(new SchemaInspector($pdo, Dialect::Sqlite), Dialect::Sqlite))->run());
        self::assertSame([], SchemaInstaller::createMissing(new PdoAdapter($pdo)), 'nothing left to create, and the seeding runs again without a duplicate');
    }
}

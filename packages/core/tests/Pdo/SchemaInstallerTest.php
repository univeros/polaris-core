<?php

declare(strict_types=1);

namespace Polaris\Tests\Pdo;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\Dialect;
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
}

<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\DatabaseManager;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use Polaris\Contract\Dialect;
use Polaris\Laravel\Console\InstallCommand;
use Polaris\Laravel\Schema\PolarisSchema;
use Polaris\Pdo\SchemaDiff;
use Polaris\Pdo\SchemaInspector;

use function bin2hex;
use function copy;
use function glob;
use function mkdir;
use function random_bytes;
use function sys_get_temp_dir;

#[CoversClass(InstallCommand::class)]
#[CoversClass(PolarisSchema::class)]
final class InstallCommandTest extends LaravelTestCase
{
    public function testInstallWritesTheMigrationAndMigrateCreatesTheSchema(): void
    {
        $root = sys_get_temp_dir() . '/polaris-laravel-' . bin2hex(random_bytes(4));
        mkdir($root . '/config', 0777, true);
        mkdir($root . '/database/migrations', 0777, true);
        $app = LaravelApp::create(resolving: static function (Application $app) use ($root): void {
            // The published config and the migration land in the temporary tree; the skeleton's config files
            // are copied so the application still boots.
            foreach (glob($app->configPath('*.php')) ?: [] as $file) {
                copy($file, $root . '/config/' . basename($file));
            }
            $app->useConfigPath($root . '/config');
            $app->useDatabasePath($root . '/database');
        });
        $config = $app->make(Repository::class);
        $config->set('database.default', 'polaris_test');
        $config->set('database.connections.polaris_test', ['driver' => 'sqlite', 'database' => ':memory:', 'foreign_key_constraints' => true]);
        $kernel = $app->make(Kernel::class);

        self::assertSame(0, $kernel->call('polaris:install'), $kernel->output());
        self::assertFileExists($root . '/config/polaris.php');
        self::assertCount(1, glob($root . '/database/migrations/*_create_polaris_tables.php') ?: []);

        self::assertSame(0, $kernel->call('migrate', ['--force' => true]), $kernel->output());
        $pdo = $app->make(DatabaseManager::class)->connection()->getPdo();
        self::assertSame([], (new SchemaDiff(new SchemaInspector($pdo, Dialect::Sqlite), Dialect::Sqlite))->run());
        self::assertGreaterThan(0, (int) $pdo->query('SELECT COUNT(*) FROM auth_roles WHERE organization_id IS NULL')->fetchColumn(), 'the system roles are seeded');
        self::assertGreaterThan(0, (int) $pdo->query('SELECT COUNT(*) FROM auth_permissions')->fetchColumn(), 'the permission catalog is seeded');

        self::assertSame(0, $kernel->call('polaris:install'), $kernel->output());
        self::assertCount(1, glob($root . '/database/migrations/*_create_polaris_tables.php') ?: [], 'install is idempotent');

        self::assertSame(0, $kernel->call('migrate:rollback', ['--force' => true]), $kernel->output());
        self::assertSame(0, (int) $pdo->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'auth_users'")->fetchColumn());
    }
}

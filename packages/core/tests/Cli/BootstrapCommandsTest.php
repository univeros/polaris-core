<?php

declare(strict_types=1);

namespace Polaris\Tests\Cli;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Cli\Application;
use Polaris\Cli\Bootstrap;
use Symfony\Component\Console\Tester\CommandTester;

use function dirname;
use function json_decode;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * `--bootstrap`: the commands see the application's plugins (their tables, routes and permissions).
 * Separate processes, because a bootstrap registers the plugin's schema statically.
 */
#[CoversClass(Bootstrap::class)]
#[RunTestsInSeparateProcesses]
final class BootstrapCommandsTest extends TestCase
{
    private const string BOOTSTRAP = __DIR__ . '/../Support/Plugin/bootstrap.php';

    public function testSchemaExportAndManifestIncludeThePlugin(): void
    {
        $app = new Application();
        $app->setAutoExit(false);

        $export = new CommandTester($app->find('schema:export'));
        self::assertSame(0, $export->execute(['--target' => 'sql:sqlite', '--bootstrap' => self::BOOTSTRAP]));
        self::assertStringContainsString('CREATE TABLE "polaris_sample_note"', $export->getDisplay());

        $manifest = new CommandTester($app->find('manifest'));
        self::assertSame(0, $manifest->execute(['--format' => 'json', '--bootstrap' => self::BOOTSTRAP]));
        self::assertCount(53, json_decode($manifest->getDisplay(), true)['endpoints']);
    }

    public function testSchemaCreateSeedsThePluginsPermissionAndSchemaDiffIsClean(): void
    {
        $app = new Application();
        $app->setAutoExit(false);
        $file = (string) tempnam(sys_get_temp_dir(), 'polaris-plugin-');
        $dsn = 'sqlite:' . $file;

        $create = new CommandTester($app->find('schema:create'));
        self::assertSame(0, $create->execute(['--dsn' => $dsn, '--bootstrap' => self::BOOTSTRAP]), $create->getDisplay());
        $pdo = new PDO($dsn);
        self::assertSame('Read the sample notes', $pdo->query("SELECT description FROM auth_permissions WHERE key = 'sample.read'")->fetchColumn());
        self::assertSame(1, (int) $pdo->query("SELECT count(*) FROM sqlite_master WHERE name = 'polaris_sample_note'")->fetchColumn());

        $diff = new CommandTester($app->find('schema:diff'));
        self::assertSame(0, $diff->execute(['--dsn' => $dsn, '--bootstrap' => self::BOOTSTRAP]), $diff->getDisplay());

        $doctor = new CommandTester($app->find('doctor'));
        $doctor->execute(['--dsn' => $dsn, '--bootstrap' => self::BOOTSTRAP]);
        self::assertStringContainsString('53 endpoints', $doctor->getDisplay());
        unlink($file);
    }

    public function testAMissingOrWrongBootstrapIsReported(): void
    {
        $app = new Application();
        $app->setAutoExit(false);
        $export = new CommandTester($app->find('schema:export'));
        $this->expectExceptionMessage('does not exist');
        $export->execute(['--bootstrap' => dirname(self::BOOTSTRAP) . '/missing.php']);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Tests\Cli;

use PDO;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Polaris\Cli\Application;
use Polaris\Contract\Dialect;
use Polaris\Pdo\SqlSchema;
use Polaris\Tests\Support\TestKeys;
use Symfony\Component\Console\Tester\CommandTester;

use function json_decode;
use function putenv;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

#[CoversNothing]
final class CommandsTest extends TestCase
{
    private Application $app;

    protected function setUp(): void
    {
        $this->app = new Application();
        $this->app->setAutoExit(false);
    }

    protected function tearDown(): void
    {
        foreach (['APP_KEY', 'AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY', 'AUTH_JWT_KID', 'AUTH_ISSUER', 'POLARIS_DSN'] as $key) {
            putenv($key);
        }
    }

    public function testSchemaExportPrintsDdlForEachDialect(): void
    {
        $tester = new CommandTester($this->app->find('schema:export'));

        self::assertSame(0, $tester->execute(['--target' => 'sql:postgres']));
        self::assertStringContainsString('CREATE TABLE "auth_users"', $tester->getDisplay());
        self::assertSame(0, $tester->execute(['--target' => 'sql:mysql']));
        self::assertStringContainsString('CREATE TABLE `auth_users`', $tester->getDisplay());
        self::assertSame(2, $tester->execute(['--target' => 'laravel']));
    }

    public function testManifestPrintsJsonAndOpenApi(): void
    {
        $tester = new CommandTester($this->app->find('manifest'));

        self::assertSame(0, $tester->execute(['--format' => 'json']));
        $json = json_decode($tester->getDisplay(), true);
        self::assertCount(52, $json['endpoints']);

        self::assertSame(0, $tester->execute(['--format' => 'openapi']));
        $openapi = json_decode($tester->getDisplay(), true);
        self::assertSame('3.1.0', $openapi['openapi']);
        $operations = 0;
        foreach ($openapi['paths'] as $methods) {
            $operations += count($methods);
        }
        self::assertSame(52, $operations);
        $login = $openapi['paths']['/auth/login']['post'];
        self::assertSame(['email', 'password'], $login['requestBody']['content']['application/json']['schema']['required']);
        self::assertSame('email', $login['requestBody']['content']['application/json']['schema']['properties']['email']['format']);
        self::assertSame(320, $login['requestBody']['content']['application/json']['schema']['properties']['email']['maxLength']);
        self::assertSame('write', $login['x-polaris-effect']);
        self::assertSame([['bearerAuth' => []]], $openapi['paths']['/auth/me']['get']['security']);
        self::assertArrayHasKey('id', $openapi['paths']['/auth/sessions/{id}']['delete']['parameters'][0]['name'] === 'id' ? ['id' => true] : []);
    }

    public function testSchemaDiffIsCleanOnAnExportedDatabaseAndReportsDrift(): void
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'polaris-schema-');
        $pdo = new PDO('sqlite:' . $file);
        foreach (SqlSchema::createAll(Dialect::Sqlite) as $statement) {
            $pdo->exec($statement);
        }
        $tester = new CommandTester($this->app->find('schema:diff'));

        self::assertSame(0, $tester->execute(['--dsn' => 'sqlite:' . $file]), $tester->getDisplay());
        self::assertStringContainsString('matches', $tester->getDisplay());

        $pdo->exec('DROP INDEX "auth_users_email_unique"');
        $pdo->exec('ALTER TABLE "auth_users" DROP COLUMN "display_name"');
        self::assertSame(1, $tester->execute(['--dsn' => 'sqlite:' . $file]));
        self::assertStringContainsString('auth_users.display_name: column is missing', $tester->getDisplay());
        self::assertStringContainsString('unique index on (email) is missing', $tester->getDisplay());
        unset($pdo);
        unlink($file);
    }

    public function testDoctorPassesWithKeysAndAnExportedDatabase(): void
    {
        $keys = TestKeys::rsa();
        putenv('APP_KEY=app-key-for-doctor-0123456789abcdef');
        putenv('AUTH_JWT_PRIVATE_KEY=' . $keys['private']);
        putenv('AUTH_JWT_PUBLIC_KEY=' . $keys['public']);
        putenv('AUTH_JWT_KID=kid-1');
        putenv('AUTH_ISSUER=https://auth.polaris.test');
        $file = (string) tempnam(sys_get_temp_dir(), 'polaris-doctor-');
        $pdo = new PDO('sqlite:' . $file);
        foreach (SqlSchema::createAll(Dialect::Sqlite) as $statement) {
            $pdo->exec($statement);
        }
        unset($pdo);
        $tester = new CommandTester($this->app->find('doctor'));

        self::assertSame(0, $tester->execute(['--dsn' => 'sqlite:' . $file]), $tester->getDisplay());
        self::assertStringContainsString('Polaris is ready', $tester->getDisplay());
        self::assertStringContainsString('manifest: 52 endpoints', $tester->getDisplay());
        unlink($file);

        putenv('AUTH_JWT_PUBLIC_KEY=not-a-key');
        self::assertSame(1, $tester->execute([]));
        self::assertStringContainsString('FAIL', $tester->getDisplay());
    }
}

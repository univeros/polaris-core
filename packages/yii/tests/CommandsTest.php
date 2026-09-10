<?php

declare(strict_types=1);

namespace Polaris\Yii\Tests;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Yiisoft\Yii\Console\Application;
use Yiisoft\Yii\Console\CommandLoader;

use function dirname;
use function json_decode;

/**
 * The polaris/cli commands under yiisoft/yii-console, on the container's connection, secrets and settings.
 */
#[CoversNothing]
final class CommandsTest extends TestCase
{
    public function testTheConsoleCarriesThePolarisCommandsOnTheConfiguredDatabase(): void
    {
        $container = YiiApp::container([
            'secrets' => Fixtures::secretsArray(),
            'auth' => ['issuer' => 'https://issuer.test'],
            'database' => ['dsn' => 'sqlite::memory:'],
        ], console: true);
        $params = require dirname(__DIR__) . '/config/params.php';
        $console = new Application();
        $console->setAutoExit(false);
        $console->setCommandLoader(new CommandLoader($container, $params['yiisoft/yii-console']['commands']));
        $run = static function (string $command, array $input = []) use ($console): array {
            $tester = new CommandTester($console->find($command));

            return [$tester->execute($input), $tester->getDisplay()];
        };

        [$status, $output] = $run('polaris:schema:diff');
        self::assertSame(1, $status, $output);
        [$status, $output] = $run('polaris:schema:create');
        self::assertSame(0, $status, $output);
        [$status, $output] = $run('polaris:schema:diff');
        self::assertSame(0, $status, $output);
        self::assertStringContainsString('matches the Polaris schema', $output);
        [$status, $output] = $run('polaris:doctor');
        self::assertSame(0, $status, $output);
        self::assertStringContainsString('Polaris is ready', $output);
        [$status, $output] = $run('polaris:manifest', ['--format' => 'json']);
        self::assertSame(0, $status, $output);
        self::assertCount(52, json_decode($output, true)['endpoints']);
        [$status, $output] = $run('polaris:schema:export', ['--target' => 'sql:sqlite']);
        self::assertSame(0, $status, $output);
        self::assertStringContainsString('CREATE TABLE "auth_users"', $output);
        [$status, $output] = $run('polaris:schema:drop');
        self::assertSame(0, $status, $output);
        [$status] = $run('polaris:schema:diff');
        self::assertSame(1, $status);
    }
}

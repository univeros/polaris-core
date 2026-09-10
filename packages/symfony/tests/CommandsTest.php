<?php

declare(strict_types=1);

namespace Polaris\Symfony\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Symfony\Command\SchemaCreateCommand;
use Polaris\Symfony\Command\SchemaDropCommand;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

use function json_decode;

#[CoversClass(SchemaCreateCommand::class)]
#[CoversClass(SchemaDropCommand::class)]
final class CommandsTest extends TestCase
{
    public function testTheConsoleCarriesThePolarisCommandsOnTheConfiguredDatabase(): void
    {
        $kernel = new TestKernel([
            'secrets' => Fixtures::secretsArray(),
            'auth' => ['issuer' => 'https://issuer.test'],
            'database' => ['dsn' => 'sqlite::memory:'],
        ]);
        $console = new Application($kernel);
        $console->setAutoExit(false);
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
        $kernel->shutdown();
    }
}

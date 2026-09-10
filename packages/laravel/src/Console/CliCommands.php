<?php

declare(strict_types=1);

namespace Polaris\Laravel\Console;

use Illuminate\Console\Application as Artisan;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\DatabaseManager;
use PDO;
use Polaris\Cli\Command\DoctorCommand;
use Polaris\Cli\Command\ManifestCommand;
use Polaris\Cli\Command\SchemaDiffCommand;
use Polaris\Cli\Command\SchemaExportCommand;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Wiring\Graph;

use function is_string;

/**
 * The polaris/cli commands under artisan as `polaris:schema:export`, `polaris:schema:diff`,
 * `polaris:manifest` and `polaris:doctor`, on the application's connection, secrets and auth settings
 * instead of POLARIS_DSN and the environment (`--dsn` still overrides).
 */
final class CliCommands
{
    public static function register(Application $app): void
    {
        Artisan::starting(static function (Artisan $artisan) use ($app): void {
            $connection = static function () use ($app): PDO {
                $name = $app->make(Repository::class)->get('polaris.database');

                return $app->make(DatabaseManager::class)->connection(is_string($name) && $name !== '' ? $name : null)->getPdo();
            };
            $graph = static fn (): Graph => $app->make(Graph::class);
            $commands = [
                new SchemaExportCommand(),
                new SchemaDiffCommand($connection),
                new ManifestCommand(),
                new DoctorCommand(
                    static fn (): Secrets => $graph()->config()->secrets,
                    static fn (): AuthConfig => $graph()->config()->auth,
                    $connection,
                ),
            ];
            foreach ($commands as $command) {
                $command->setName('polaris:' . $command->getName());
                $artisan->addCommand($command);
            }
        });
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Cli;

use Polaris\Cli\Command\DoctorCommand;
use Polaris\Cli\Command\ManifestCommand;
use Polaris\Cli\Command\SchemaCreateCommand;
use Polaris\Cli\Command\SchemaDiffCommand;
use Polaris\Cli\Command\SchemaDropCommand;
use Polaris\Cli\Command\SchemaExportCommand;
use Polaris\Polaris;
use Symfony\Component\Console\Application as Console;

final class Application extends Console
{
    /**
     * @param Polaris|null $polaris the application (from `Bootstrap::load()`), whose plugins may add commands
     */
    public function __construct(?Polaris $polaris = null)
    {
        parent::__construct('polaris', '0.2.0');
        $this->addCommands([
            new SchemaExportCommand(),
            new SchemaCreateCommand(),
            new SchemaDropCommand(),
            new SchemaDiffCommand(),
            new ManifestCommand(),
            new DoctorCommand(),
        ]);
        if ($polaris !== null) {
            foreach ($polaris->graph()->plugins() as $plugin) {
                if ($plugin instanceof CommandProvider) {
                    $this->addCommands($plugin->commands($polaris->graph()));
                }
            }
        }
    }
}

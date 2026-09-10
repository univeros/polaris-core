<?php

declare(strict_types=1);

namespace Polaris\Cli;

use Polaris\Cli\Command\DoctorCommand;
use Polaris\Cli\Command\ManifestCommand;
use Polaris\Cli\Command\SchemaCreateCommand;
use Polaris\Cli\Command\SchemaDiffCommand;
use Polaris\Cli\Command\SchemaDropCommand;
use Polaris\Cli\Command\SchemaExportCommand;
use Symfony\Component\Console\Application as Console;

final class Application extends Console
{
    public function __construct()
    {
        parent::__construct('polaris', '0.1.0');
        $this->addCommands([
            new SchemaExportCommand(),
            new SchemaCreateCommand(),
            new SchemaDropCommand(),
            new SchemaDiffCommand(),
            new ManifestCommand(),
            new DoctorCommand(),
        ]);
    }
}

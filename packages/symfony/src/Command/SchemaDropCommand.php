<?php

declare(strict_types=1);

namespace Polaris\Symfony\Command;

use Closure;
use PDO;
use Polaris\Pdo\SchemaInstaller;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `polaris:schema:drop`: drops every Polaris table on the configured database.
 */
final class SchemaDropCommand extends Command
{
    private readonly Closure $connection;

    /**
     * @param callable(): PDO $connection
     */
    public function __construct(callable $connection)
    {
        $this->connection = $connection(...);
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setName('polaris:schema:drop')->setDescription('Drops the Polaris tables.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        SchemaInstaller::drop(($this->connection)());
        $output->writeln('<info>Dropped the Polaris tables.</info>');

        return Command::SUCCESS;
    }
}

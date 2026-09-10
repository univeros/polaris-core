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
 * `polaris:schema:create`: the Polaris tables for the connection's dialect, the permission catalog and
 * the system roles, on the configured database. `polaris:schema:diff` proves the result.
 */
final class SchemaCreateCommand extends Command
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
        $this->setName('polaris:schema:create')->setDescription('Creates the Polaris tables and seeds the permission catalog and the system roles.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        SchemaInstaller::create(($this->connection)());
        $output->writeln('<info>Created the Polaris tables and seeded the permission catalog and the system roles.</info>');

        return Command::SUCCESS;
    }
}

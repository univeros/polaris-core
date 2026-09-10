<?php

declare(strict_types=1);

namespace Polaris\Cli\Command;

use Closure;
use PDO;
use Polaris\Cli\Database;
use Polaris\Pdo\SchemaInstaller;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function sprintf;

/**
 * `schema:drop`: drops every Polaris table on the connection.
 */
final class SchemaDropCommand extends Command
{
    private readonly ?Closure $connection;

    /**
     * @param (callable(): PDO)|null $connection the host's connection, used when no `--dsn` is given
     */
    public function __construct(?callable $connection = null)
    {
        $this->connection = $connection === null ? null : $connection(...);
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('schema:drop')
            ->setDescription('Drops the Polaris tables.')
            ->addOption('dsn', null, InputOption::VALUE_REQUIRED, 'PDO DSN (or POLARIS_DSN)')
            ->addOption('user', null, InputOption::VALUE_REQUIRED, 'Database user (or POLARIS_DB_USER)')
            ->addOption('password', null, InputOption::VALUE_REQUIRED, 'Database password (or POLARIS_DB_PASSWORD)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $dsn = Database::dsn($input->getOption('dsn'));
        if ($dsn === null && $this->connection === null) {
            $output->writeln('<error>Pass --dsn or set POLARIS_DSN.</error>');

            return Command::INVALID;
        }
        try {
            SchemaInstaller::drop($dsn === null ? ($this->connection)() : Database::connect($dsn, $input->getOption('user'), $input->getOption('password')));
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        $output->writeln('<info>Dropped the Polaris tables.</info>');

        return Command::SUCCESS;
    }
}

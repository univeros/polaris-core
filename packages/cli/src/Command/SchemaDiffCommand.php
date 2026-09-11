<?php

declare(strict_types=1);

namespace Polaris\Cli\Command;

use Polaris\Cli\Bootstrap;
use Closure;
use PDO;
use Polaris\Cli\Database;
use Polaris\Pdo\SchemaDiff;
use Polaris\Pdo\SchemaInspector;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function count;
use function sprintf;

final class SchemaDiffCommand extends Command
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
            ->setName('schema:diff')
            ->setDescription('Compares the Polaris schema with a live database.')
            ->addOption('dsn', null, InputOption::VALUE_REQUIRED, 'PDO DSN (or POLARIS_DSN)')
            ->addOption('user', null, InputOption::VALUE_REQUIRED, 'Database user (or POLARIS_DB_USER)')
            ->addOption('password', null, InputOption::VALUE_REQUIRED, 'Database password (or POLARIS_DB_PASSWORD)')
            ->addOption('bootstrap', 'b', InputOption::VALUE_REQUIRED, 'A PHP file returning the application\'s Polaris instance or Config, so the plugins\' tables and routes are included (or POLARIS_BOOTSTRAP)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        Bootstrap::load($input->getOption('bootstrap'));
        $dsn = Database::dsn($input->getOption('dsn'));
        if ($dsn === null && $this->connection === null) {
            $output->writeln('<error>Pass --dsn or set POLARIS_DSN.</error>');

            return Command::INVALID;
        }
        try {
            $pdo = $dsn === null ? ($this->connection)() : Database::connect($dsn, $input->getOption('user'), $input->getOption('password'));
            $dialect = $dsn === null ? Database::dialectOf($pdo) : Database::dialect($dsn);
            $differences = (new SchemaDiff(new SchemaInspector($pdo, $dialect), $dialect))->run();
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        if ($differences === []) {
            $output->writeln('<info>The database matches the Polaris schema.</info>');

            return Command::SUCCESS;
        }
        foreach ($differences as $difference) {
            $output->writeln(' - ' . $difference);
        }
        $output->writeln(sprintf('<comment>%d difference(s).</comment>', count($differences)));

        return Command::FAILURE;
    }
}

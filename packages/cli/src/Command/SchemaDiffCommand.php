<?php

declare(strict_types=1);

namespace Polaris\Cli\Command;

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
    protected function configure(): void
    {
        $this
            ->setName('schema:diff')
            ->setDescription('Compares the Polaris schema with a live database.')
            ->addOption('dsn', null, InputOption::VALUE_REQUIRED, 'PDO DSN (or POLARIS_DSN)')
            ->addOption('user', null, InputOption::VALUE_REQUIRED, 'Database user (or POLARIS_DB_USER)')
            ->addOption('password', null, InputOption::VALUE_REQUIRED, 'Database password (or POLARIS_DB_PASSWORD)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $dsn = Database::dsn($input->getOption('dsn'));
        if ($dsn === null) {
            $output->writeln('<error>Pass --dsn or set POLARIS_DSN.</error>');

            return Command::INVALID;
        }
        try {
            $pdo = Database::connect($dsn, $input->getOption('user'), $input->getOption('password'));
            $differences = (new SchemaDiff(new SchemaInspector($pdo, Database::dialect($dsn)), Database::dialect($dsn)))->run();
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

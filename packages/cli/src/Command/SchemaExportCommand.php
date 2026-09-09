<?php

declare(strict_types=1);

namespace Polaris\Cli\Command;

use Polaris\Contract\Dialect;
use Polaris\Pdo\SqlSchema;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use function implode;
use function sprintf;

final class SchemaExportCommand extends Command
{
    private const array SQL_TARGETS = ['sql:postgres' => Dialect::Postgres, 'sql:mysql' => Dialect::Mysql, 'sql:sqlite' => Dialect::Sqlite];

    protected function configure(): void
    {
        $this
            ->setName('schema:export')
            ->setDescription('Prints the Polaris schema as DDL for a database dialect.')
            ->addOption('target', 't', InputOption::VALUE_REQUIRED, 'sql:postgres | sql:mysql | sql:sqlite', 'sql:postgres')
            ->addOption('drop', null, InputOption::VALUE_NONE, 'Emit DROP TABLE statements instead');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $target = (string) $input->getOption('target');
        $dialect = self::SQL_TARGETS[$target] ?? null;
        if ($dialect === null) {
            $output->writeln(sprintf('<error>Unknown target "%s". Available: %s. The laravel, doctrine and cycle targets ship with their adapter packages.</error>', $target, implode(', ', array_keys(self::SQL_TARGETS))));

            return Command::INVALID;
        }
        $statements = $input->getOption('drop') === true ? SqlSchema::dropAll($dialect) : SqlSchema::createAll($dialect);
        $output->writeln(implode(";\n\n", $statements) . ";");

        return Command::SUCCESS;
    }
}

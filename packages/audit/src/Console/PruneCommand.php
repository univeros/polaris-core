<?php

declare(strict_types=1);

namespace Polaris\Audit\Console;

use Polaris\Audit\AuditPlugin;
use Polaris\Cli\Bootstrap;
use Polaris\Wiring\Graph;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function sprintf;

/**
 * `polaris audit:prune`: applies the retention policy.
 */
#[AsCommand(name: 'audit:prune', description: 'Deletes the audit events the retention policy no longer keeps.')]
final class PruneCommand extends Command
{
    /** @var (callable(): Graph)|null */
    private $graph;

    /**
     * @param callable(): Graph|null $graph the application's graph; without one, `--bootstrap` names the application
     */
    public function __construct(?callable $graph = null)
    {
        $this->graph = $graph === null ? null : $graph(...);
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('bootstrap', 'b', InputOption::VALUE_REQUIRED, 'A PHP file returning the application\'s Polaris instance or Config (or POLARIS_BOOTSTRAP)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $graph = $this->graph === null ? Bootstrap::load($input->getOption('bootstrap'))?->graph() : ($this->graph)();
            if ($graph === null) {
                $output->writeln('<error>Pass --bootstrap or set POLARIS_BOOTSTRAP: the retention policy is the application\'s.</error>');

                return Command::INVALID;
            }
            $deleted = AuditPlugin::of($graph)->pruner($graph)->prune();
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        $output->writeln(sprintf('<info>Pruned %d audit event(s).</info>', $deleted));

        return Command::SUCCESS;
    }
}

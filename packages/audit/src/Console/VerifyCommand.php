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

use function count;
use function sprintf;

/**
 * `polaris audit:verify`: walks the hash chain and reports every break.
 */
#[AsCommand(name: 'audit:verify', description: 'Verifies the audit hash chain.')]
final class VerifyCommand extends Command
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
                $output->writeln('<error>Pass --bootstrap or set POLARIS_BOOTSTRAP.</error>');

                return Command::INVALID;
            }
            $report = AuditPlugin::of($graph)->verifier($graph)->verify();
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        foreach ($report['breaks'] as $break) {
            $output->writeln(sprintf('<error>%s</error>', $break));
        }
        $output->writeln(sprintf('%s: %d event(s) checked, %d break(s).', $report['breaks'] === [] ? '<info>Chain intact</info>' : '<error>Chain broken</error>', $report['rows'], count($report['breaks'])));

        return $report['breaks'] === [] ? Command::SUCCESS : Command::FAILURE;
    }
}

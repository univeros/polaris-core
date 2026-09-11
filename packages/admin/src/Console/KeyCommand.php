<?php

declare(strict_types=1);

namespace Polaris\Admin\Console;

use DateTimeImmutable;
use Polaris\Admin\Keys;
use Polaris\Admin\Principal\IpAllowlist;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Cli\Bootstrap;
use Polaris\Wiring\Graph;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function array_filter;
use function array_map;
use function explode;
use function is_string;
use function sprintf;
use function trim;

/**
 * `polaris admin:key <name> <role>`: creates an API key and prints it once.
 */
#[AsCommand(name: 'admin:key', description: 'Creates an admin API key and prints it once.')]
final class KeyCommand extends Command
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
        $this
            ->addArgument('name', InputArgument::REQUIRED, 'What the key is for (a dashboard, an integration)')
            ->addArgument('role', InputArgument::REQUIRED, 'viewer, support, admin or owner')
            ->addOption('scope', 's', InputOption::VALUE_REQUIRED, 'instance, or an organization id', Principal::SCOPE_INSTANCE)
            ->addOption('allow', 'a', InputOption::VALUE_REQUIRED, 'Comma-separated addresses or CIDR blocks the key may be used from')
            ->addOption('expires', 'e', InputOption::VALUE_REQUIRED, 'An ISO-8601 datetime after which the key stops working')
            ->addOption('bootstrap', 'b', InputOption::VALUE_REQUIRED, 'A PHP file returning the application\'s Polaris instance or Config (or POLARIS_BOOTSTRAP)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $role = Role::tryFromInput($input->getArgument('role'));
        if ($role === null) {
            $output->writeln('<error>role must be viewer, support, admin or owner.</error>');

            return Command::INVALID;
        }
        $allow = $input->getOption('allow');
        $allowlist = is_string($allow) ? array_values(array_filter(array_map(trim(...), explode(',', $allow)), static fn(string $entry): bool => $entry !== '')) : [];
        foreach ($allowlist as $entry) {
            if (!IpAllowlist::isValid($entry)) {
                $output->writeln(sprintf('<error>"%s" is not an address or a CIDR block.</error>', $entry));

                return Command::INVALID;
            }
        }
        try {
            $expires = $input->getOption('expires');
            $expiresAt = is_string($expires) && $expires !== '' ? new DateTimeImmutable($expires) : null;
            $graph = $this->graph === null ? Bootstrap::load($input->getOption('bootstrap'))?->graph() : ($this->graph)();
            if ($graph === null) {
                $output->writeln('<error>Pass --bootstrap or set POLARIS_BOOTSTRAP: the keys are the application\'s.</error>');

                return Command::INVALID;
            }
            $scope = $input->getOption('scope');
            $issued = $graph->get(Keys::class)->create((string) $input->getArgument('name'), $role, is_string($scope) && $scope !== '' ? $scope : Principal::SCOPE_INSTANCE, $allowlist, $expiresAt, 'cli');
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        $output->writeln(sprintf('<info>Created key %s (%s, %s, scope %s).</info>', $issued->key->id, $issued->key->name, $issued->key->role, $issued->key->scope));
        $output->writeln('The key is shown once; store it now:');
        $output->writeln($issued->plaintext);

        return Command::SUCCESS;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Admin\Console;

use DateTimeImmutable;
use Polaris\Admin\Grants;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Cli\Bootstrap;
use Polaris\Model\User;
use Polaris\Wiring\Graph;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function is_string;
use function sprintf;

/**
 * `polaris admin:grant <email> <role>`: gives a user an operator role (replacing their grant).
 */
#[AsCommand(name: 'admin:grant', description: 'Grants an admin role to a user, by email.')]
final class GrantCommand extends Command
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
            ->addArgument('email', InputArgument::REQUIRED, 'The user\'s email address')
            ->addArgument('role', InputArgument::REQUIRED, 'viewer, support, admin or owner')
            ->addOption('scope', 's', InputOption::VALUE_REQUIRED, 'instance, or an organization id', Principal::SCOPE_INSTANCE)
            ->addOption('expires', 'e', InputOption::VALUE_REQUIRED, 'An ISO-8601 datetime after which the grant lapses')
            ->addOption('bootstrap', 'b', InputOption::VALUE_REQUIRED, 'A PHP file returning the application\'s Polaris instance or Config (or POLARIS_BOOTSTRAP)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $role = Role::tryFromInput($input->getArgument('role'));
        if ($role === null) {
            $output->writeln('<error>role must be viewer, support, admin or owner.</error>');

            return Command::INVALID;
        }
        try {
            $expires = $input->getOption('expires');
            $expiresAt = is_string($expires) && $expires !== '' ? new DateTimeImmutable($expires) : null;
            $graph = $this->graph === null ? Bootstrap::load($input->getOption('bootstrap'))?->graph() : ($this->graph)();
            if ($graph === null) {
                $output->writeln('<error>Pass --bootstrap or set POLARIS_BOOTSTRAP: the grants are the application\'s.</error>');

                return Command::INVALID;
            }
            $user = $graph->users()->findOneBy(['email' => (string) $input->getArgument('email')]);
            if (!$user instanceof User) {
                $output->writeln('<error>No user has that email address.</error>');

                return Command::FAILURE;
            }
            $scope = $input->getOption('scope');
            $grant = $graph->get(Grants::class)->grant($user->id, $role, is_string($scope) && $scope !== '' ? $scope : Principal::SCOPE_INSTANCE, $expiresAt, 'cli');
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        $output->writeln(sprintf('<info>Granted %s to %s (scope %s, grant %s).</info>', $grant->role, $user->email, $grant->scope, $grant->id));

        return Command::SUCCESS;
    }
}

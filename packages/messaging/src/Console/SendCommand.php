<?php

declare(strict_types=1);

namespace Polaris\Messaging\Console;

use Polaris\Cli\Bootstrap;
use Polaris\Messaging\Message;
use Polaris\Messaging\Sender;
use Polaris\Wiring\Graph;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function is_string;
use function json_decode;
use function sprintf;
use function str_starts_with;

/**
 * `polaris messaging:send <to> <template>`: renders and sends one message through the application's
 * channels, to check a channel and a template from the console.
 */
#[AsCommand(name: 'messaging:send', description: 'Sends one templated message through the configured channels.')]
final class SendCommand extends Command
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
            ->addArgument('to', InputArgument::REQUIRED, 'An email address or an E.164 number')
            ->addArgument('template', InputArgument::REQUIRED, 'A template key (email.verify, sms.otp, ...); its kind decides the channel')
            ->addOption('vars', null, InputOption::VALUE_REQUIRED, 'The template variables as JSON', '{}')
            ->addOption('locale', 'l', InputOption::VALUE_REQUIRED, 'The locale (the plugin\'s default otherwise)')
            ->addOption('bootstrap', 'b', InputOption::VALUE_REQUIRED, 'A PHP file returning the application\'s Polaris instance or Config (or POLARIS_BOOTSTRAP)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $template = (string) $input->getArgument('template');
        $kind = str_starts_with($template, Message::SMS . '.') ? Message::SMS : Message::EMAIL;
        $vars = json_decode((string) $input->getOption('vars'), true);
        if (!is_array($vars)) {
            $output->writeln('<error>--vars must be a JSON object.</error>');

            return Command::INVALID;
        }
        try {
            $graph = $this->graph === null ? Bootstrap::load($input->getOption('bootstrap'))?->graph() : ($this->graph)();
            if ($graph === null) {
                $output->writeln('<error>Pass --bootstrap or set POLARIS_BOOTSTRAP: the channels are the application\'s.</error>');

                return Command::INVALID;
            }
            $locale = $input->getOption('locale');
            $receipt = $graph->get(Sender::class)->send($kind, (string) $input->getArgument('to'), $template, $vars, is_string($locale) && $locale !== '' ? $locale : null, essential: true);
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        if ($receipt === null) {
            $output->writeln('<error>Not sent: no channel delivered it (see the log).</error>');

            return Command::FAILURE;
        }
        $output->writeln(sprintf('<info>Sent %s to %s through %s%s.</info>', $template, $input->getArgument('to'), $receipt->channel, $receipt->providerId === null ? '' : ' (' . $receipt->providerId . ')'));

        return Command::SUCCESS;
    }
}

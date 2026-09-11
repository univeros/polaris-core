<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Console;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

use function count;
use function file_put_contents;
use function is_string;
use function preg_split;
use function sprintf;
use function strtolower;
use function trim;

/**
 * `polaris sentinel:lists --url=<list>`: refreshes the disposable-domain list from a URL the host
 * chooses (one domain per line) into the plugin's list file. Without a URL nothing is fetched: the
 * bundled list is refreshed per release.
 */
#[AsCommand(name: 'sentinel:lists', description: 'Refreshes the disposable email domain list from a URL.')]
final class ListsCommand extends Command
{
    public function __construct(
        private readonly ?ClientInterface $client,
        private readonly ?RequestFactoryInterface $requests,
        private readonly string $file,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('url', 'u', InputOption::VALUE_REQUIRED, 'Where to fetch the list (one domain per line)')
            ->addOption('to', 't', InputOption::VALUE_REQUIRED, 'The file to write (the plugin\'s list file by default)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $url = $input->getOption('url');
        if (!is_string($url) || $url === '') {
            $output->writeln('<error>Pass --url: the list has no default source.</error>');

            return Command::INVALID;
        }
        if ($this->client === null || $this->requests === null) {
            $output->writeln('<error>The sentinel plugin has no HTTP client (httpClient, requestFactory).</error>');

            return Command::FAILURE;
        }
        try {
            $response = $this->client->sendRequest($this->requests->createRequest('GET', $url));
            if ($response->getStatusCode() !== 200) {
                $output->writeln(sprintf('<error>%s answered HTTP %d.</error>', $url, $response->getStatusCode()));

                return Command::FAILURE;
            }
            $domains = [];
            foreach (preg_split('/\R/', (string) $response->getBody()) ?: [] as $line) {
                $line = strtolower(trim($line));
                if ($line !== '' && $line[0] !== '#') {
                    $domains[$line] = true;
                }
            }
            $to = $input->getOption('to');
            $file = is_string($to) && $to !== '' ? $to : $this->file;
            file_put_contents($file, sprintf("# Disposable email domains, one per line. Source: %s.\n", $url) . implode("\n", array_keys($domains)) . "\n");
        } catch (Throwable $exception) {
            $output->writeln(sprintf('<error>%s</error>', $exception->getMessage()));

            return Command::FAILURE;
        }
        $output->writeln(sprintf('<info>Wrote %d domains to %s.</info>', count($domains), $file));

        return Command::SUCCESS;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Mcp\Console;

use Override;
use Polaris\Mcp\McpException;
use Polaris\Mcp\Principals;
use Polaris\Mcp\Server\McpServer;
use Polaris\Mcp\Transport\Stdio;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

use function getenv;
use function is_string;
use function sprintf;

/**
 * `bin/polaris mcp`: Polaris as an MCP server over stdio for a local coding agent, as the principal
 * `--token` (or `POLARIS_MCP_TOKEN`) resolves to: a session token, an API key (`pk_`), an OAuth access
 * token, an operator key (`pak_`); none for the public tools alone. The CLI commands are tools here.
 * Available when `POLARIS_BOOTSTRAP` names the application (the plugin registers it).
 */
final class McpCommand extends Command
{
    public const string ENV = 'POLARIS_MCP_TOKEN';

    /** @var resource|null */
    private $input = null;
    /** @var resource|null */
    private $output = null;

    public function __construct(private readonly Principals $principals, private readonly McpServer $server, private readonly ?LoggerInterface $logger = null)
    {
        parent::__construct();
    }

    /**
     * The streams to serve on instead of STDIN and STDOUT (a test).
     *
     * @param resource $input
     * @param resource $output
     */
    public function withStreams($input, $output): self
    {
        $this->input = $input;
        $this->output = $output;

        return $this;
    }

    #[Override]
    protected function configure(): void
    {
        $this
            ->setName('mcp')
            ->setDescription('Serves Polaris as an MCP server over stdio: every endpoint the principal may call, and the CLI commands, as tools.')
            ->addOption('token', 't', InputOption::VALUE_REQUIRED, sprintf('The credential to act as (or %s): a session token, an API key, an OAuth access token, an operator key', self::ENV));
    }

    #[Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $token = $input->getOption('token');
        $credential = is_string($token) && $token !== '' ? $token : getenv(self::ENV);
        try {
            $principal = $this->principals->fromCredential(is_string($credential) ? $credential : null);
        } catch (McpException $exception) {
            // stderr: stdout is the protocol stream.
            ($output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output)->writeln(sprintf('<error>%s</error>', $exception->detail));

            return Command::FAILURE;
        }

        return (new Stdio($this->server->builder($principal, cli: true), $this->logger))->run($this->input, $this->output);
    }
}

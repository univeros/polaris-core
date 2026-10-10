<?php

declare(strict_types=1);

namespace Polaris\Mcp\Server;

use Mcp\Schema\Tool as ToolDefinition;
use Mcp\Schema\ToolAnnotations;
use Mcp\Server;
use Mcp\Server\Builder;
use Polaris\Mcp\Principal;
use Polaris\Mcp\Tool;
use Polaris\Wiring\Graph;
use Psr\Log\LoggerInterface;

/**
 * Polaris as an MCP server: the SDK's builder assembled for one principal, with the tools the
 * principal may call ({@see ManifestTools}, the plugins' {@see \Polaris\Mcp\ToolProvider}s and, over
 * stdio, the CLI commands), the resources and the problem template. Built per request over HTTP (the
 * stateless profile has no session to carry a tool list) and once per `bin/polaris mcp` process.
 */
final class McpServer
{
    public const string VERSION = '0.10.0';
    private const int PAGE = 200;

    public function __construct(
        private readonly Graph $graph,
        private readonly ManifestTools $tools,
        private readonly string $name,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * @param bool $cli whether the CLI commands are tools (stdio only)
     */
    public function builder(Principal $principal, bool $cli = false): Builder
    {
        $builder = Server::builder()
            ->setServerInfo($this->name, self::VERSION, 'Polaris for PHP: every endpoint and CLI command as a tool, under the caller\'s own permissions.')
            ->setInstructions('Tools are named polaris.<route> and answer {status, body}: what the HTTP route answers for the same request. A 4xx or 5xx status is an error result.')
            ->setPaginationLimit(self::PAGE)
            ->setLazyLoading(false);
        if ($this->logger !== null) {
            $builder->setLogger($this->logger);
        }
        $tools = $this->tools->for($principal);
        if ($cli) {
            $tools = [...$tools, ...CliTools::tools()];
        }
        foreach ($tools as $tool) {
            $builder->add(self::definition($tool), new ToolHandler($tool));
        }
        $resources = new Resources($this->graph);
        foreach ($resources->definitions() as [$definition, $handler]) {
            $builder->add($definition, $handler);
        }
        [$template, $handler] = $resources->problems();
        $builder->add($template, $handler);

        return $builder;
    }

    private static function definition(Tool $tool): ToolDefinition
    {
        return new ToolDefinition(
            $tool->name,
            null,
            $tool->inputSchema,
            $tool->description,
            new ToolAnnotations(readOnlyHint: $tool->readOnly, destructiveHint: $tool->destructive),
            outputSchema: $tool->outputSchema,
        );
    }
}

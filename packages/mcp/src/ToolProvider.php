<?php

declare(strict_types=1);

namespace Polaris\Mcp;

use Polaris\Contract\TokenInterface;
use Polaris\Wiring\Graph;

/**
 * A plugin that adds MCP tools beyond its manifest routes (`polaris/agents`: every capability, executed
 * with its grant, budget and receipt). The MCP server asks every registered plugin implementing it, for
 * the principal of the call; a tool a principal may not use is simply not returned.
 */
interface ToolProvider
{
    /**
     * @param TokenInterface|null $principal who calls (null: no credential)
     * @return list<Tool>
     */
    public function mcpTools(Graph $graph, ?TokenInterface $principal): array;
}

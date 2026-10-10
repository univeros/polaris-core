<?php

declare(strict_types=1);

namespace Polaris\Mcp\Server;

use Polaris\Authorization\ResolvedAuthority;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Mcp\McpPlugin;
use Polaris\Mcp\Principal;
use Polaris\Mcp\Tool;
use Polaris\Mcp\ToolProvider;
use Polaris\Psr15\Middleware\AuthorizationMiddleware;
use Polaris\Wiring\Graph;

use function in_array;

/**
 * One tool per manifest route the principal may call: public routes (never an `mfa_token` one), bearer
 * routes whose permissions the principal's authority holds and core's delegation rule allows, routes
 * tagged `admin` for an operator; plus the tools every plugin implementing {@see ToolProvider} adds for
 * the principal. The mcp plugin's own routes are not tools.
 */
final class ManifestTools
{
    private const string ADMIN_TAG = 'admin';

    private ?ToolSchema $schema = null;

    public function __construct(private readonly Graph $graph, private readonly Dispatcher $dispatcher)
    {
    }

    /**
     * @return list<Tool>
     */
    public function for(Principal $principal): array
    {
        $this->schema ??= new ToolSchema($this->graph->manifest());
        $authority = $principal->token === null ? null : $this->graph->gate()->authority($principal->token);
        $tools = [];
        foreach ($this->graph->manifest()->endpoints() as $spec) {
            if (self::allows($spec, $principal, $authority)) {
                $tools[] = $this->tool($spec, $principal);
            }
        }
        foreach ($this->graph->plugins() as $plugin) {
            if ($plugin instanceof ToolProvider) {
                foreach ($plugin->mcpTools($this->graph, $principal->token) as $tool) {
                    $tools[] = $tool;
                }
            }
        }

        return $tools;
    }

    /**
     * Every route's tool regardless of a caller, for naming and schema checks.
     *
     * @return list<Tool>
     */
    public function all(): array
    {
        $this->schema ??= new ToolSchema($this->graph->manifest());
        $tools = [];
        foreach ($this->graph->manifest()->endpoints() as $spec) {
            if ($spec->plugin !== McpPlugin::ID) {
                $tools[] = $this->tool($spec, Principal::anonymous());
            }
        }

        return $tools;
    }

    private static function allows(EndpointSpec $spec, Principal $principal, ?ResolvedAuthority $authority): bool
    {
        if ($spec->plugin === McpPlugin::ID || $spec->auth === 'mfa_token') {
            return false;
        }
        if (in_array(self::ADMIN_TAG, $spec->tags, true)) {
            return $principal->operator;
        }
        if ($spec->auth === 'public') {
            return true;
        }
        if ($principal->token === null || $authority === null) {
            return false;
        }
        $required = AuthorizationMiddleware::requiredPermissions($spec);
        if (AuthorizationMiddleware::deniesDelegate($spec, $required, $principal->token)) {
            return false;
        }
        foreach ($required as $permission) {
            if (!in_array($permission, $authority->scope, true)) {
                return false;
            }
        }

        return true;
    }

    private function tool(EndpointSpec $spec, Principal $principal): Tool
    {
        $schema = $this->schema ?? new ToolSchema($this->graph->manifest());

        return new Tool(
            ToolSchema::name($spec),
            ToolSchema::description($spec),
            $schema->input($spec),
            fn(array $arguments): array => $this->dispatcher->call($spec, $arguments, $principal),
            $schema->output($spec),
            readOnly: $spec->effect === 'read',
            destructive: $spec->effect === 'destructive',
        );
    }
}

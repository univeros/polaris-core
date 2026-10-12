<?php

declare(strict_types=1);

namespace Polaris\Agents;

use LogicException;
use Override;
use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Http\AgentPrincipalMiddleware;
use Polaris\Agents\Http\AgentRequestMiddleware;
use Polaris\Agents\Http\Problems;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Contract\TokenInterface;
use Polaris\Event\MemberRemoved;
use Polaris\Event\OrganizationDeleted;
use Polaris\Event\UserDeleted;
use Polaris\Mcp\Tool;
use Polaris\Mcp\ToolProvider;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Jwt;
use Polaris\OAuth\OAuthPlugin;
use Polaris\OAuth\Tokens;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;

use function array_diff_key;
use function dirname;
use function sprintf;

/**
 * The agents plugin: `new AgentsPlugin(baseUrl: 'https://app.example.com/auth', capabilities: [...])` in
 * `Config::$plugins`, after `AuditPlugin`, `AdminPlugin` and `OAuthPlugin`. AI agents as principals:
 * registered by their owners or enrolled by hosts, each an OAuth client (client credentials for an
 * autonomous agent, token exchange for a delegated one, `private_key_jwt`, a secret or the user's token),
 * signed request JWTs, capability grants with constraints and budgets approved by a person or by
 * policy, one execution path with a signed receipt chain, and a kill switch. Every capability is also an
 * MCP tool when polaris/mcp is registered.
 */
final class AgentsPlugin extends AbstractPlugin implements ToolProvider
{
    public const string ID = 'agents';
    public const string MCP_PLUGIN = 'mcp';

    private readonly Settings $settings;
    private readonly Capabilities $capabilities;

    /**
     * @param list<Capability|array<string, mixed>> $capabilities
     * @param array<string, array<string, mixed>|true> $autoApprove risk tiers approved by policy, with their default budget
     * @param array<string, string> $strengths the approval strength per risk tier
     * @param string|null $approvalUrl the host's approval page, where a person types a user code
     */
    public function __construct(
        string $baseUrl,
        array $capabilities = [],
        array $autoApprove = Settings::DEFAULT_AUTO_APPROVE,
        array $strengths = [],
        ?string $approvalUrl = null,
        int $approvalTtl = 600,
        string $providerName = 'Polaris',
        string $description = 'Polaris for PHP agent provider',
        int $requestJwtMaxAge = 300,
        private readonly ?ResponseFactoryInterface $responses = null,
    ) {
        $this->settings = new Settings($baseUrl, $approvalUrl, $autoApprove, $strengths, $approvalTtl, $providerName, $description, $requestJwtMaxAge);
        $this->capabilities = new Capabilities($capabilities);
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The agents plugin is not registered.');
        }

        return $plugin;
    }

    public function settings(): Settings
    {
        return $this->settings;
    }

    public function capabilities(): Capabilities
    {
        return $this->capabilities;
    }

    #[Override]
    public function id(): string
    {
        return self::ID;
    }

    #[Override]
    public function schema(): array
    {
        return Schema::models();
    }

    #[Override]
    public static function manifestDirectory(): string
    {
        return dirname(__DIR__) . '/api';
    }

    /**
     * The capabilities' permissions core's catalog lacks, so they can be attached to roles and asked
     * for as OAuth scopes. Core's own permissions keep their descriptions.
     */
    #[Override]
    public function permissions(): array
    {
        return array_diff_key($this->capabilities->permissions(), (new PermissionCatalog())->permissions());
    }

    #[Override]
    public function services(): array
    {
        return [
            Settings::class => fn(): Settings => $this->settings,
            Capabilities::class => fn(): Capabilities => $this->capabilities,
            Hosts::class => fn(Graph $graph): Hosts => new Hosts($graph->database(), $graph->pepper(), $this->capabilities, $graph->clock()),
            Grants::class => fn(Graph $graph): Grants => new Grants($graph->database(), $this->capabilities, $this->settings, $graph->permissionResolver(), $graph->get(Clients::class), $graph->clock()),
            Approvals::class => fn(Graph $graph): Approvals => new Approvals($graph->database(), $graph->get(Grants::class), $this->settings, $graph->mfaVerifier(), $graph->config()->auth, $graph->clock()),
            Receipts::class => static fn(Graph $graph): Receipts => new Receipts($graph->database(), $graph->tokenConfiguration(), $graph->config()->secrets, $graph->get(Jwt::class), $graph->clock()),
            Agents::class => static fn(Graph $graph): Agents => new Agents($graph->database(), $graph->get(Clients::class), $graph->get(Tokens::class), $graph->get(Grants::class), $graph->get(Approvals::class), $graph->get(Receipts::class), $graph->clock()),
            GrantRequests::class => fn(Graph $graph): GrantRequests => new GrantRequests($graph->get(Grants::class), $graph->get(Approvals::class), $this->capabilities, $this->settings, $graph->database(), $graph->events()),
            Registrations::class => static fn(Graph $graph): Registrations => new Registrations($graph->get(Agents::class), $graph->get(GrantRequests::class), $graph->database(), $graph->events()),
            KillSwitch::class => static fn(Graph $graph): KillSwitch => new KillSwitch($graph->get(Agents::class), $graph->events()),
            RequestJwt::class => fn(Graph $graph): RequestJwt => new RequestJwt($this->settings, $graph->cache(), $graph->clock()),
            AgentAuthenticator::class => fn(Graph $graph): AgentAuthenticator => new AgentAuthenticator($graph->get(Agents::class), $graph->get(RequestJwt::class), $this->capabilities, static fn() => OAuthPlugin::of($graph)->bearerResolvers($graph)[0]),
            Executor::class => fn(Graph $graph): Executor => new Executor($this->capabilities, $graph->get(Grants::class), $graph->get(Receipts::class), $graph->database(), $graph->events(), $graph->clock()),
            Discovery::class => fn(Graph $graph): Discovery => $this->discovery($graph),
            Problems::class => fn(Graph $graph): Problems => new Problems($this->responses ?? $graph->config()->responseFactory ?? Problems::discover()),
        ];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        return [new AgentPrincipalMiddleware($graph->get(AgentAuthenticator::class), $graph->get(Grants::class), $graph->get(Problems::class))];
    }

    /**
     * The PSR-15 middleware a host puts in front of the routes that are capabilities' locations. Bound to
     * a capability (`requestMiddleware($graph, 'billing.refund')`, attached to that route), every request
     * through it must authenticate for that capability; unbound, it guards the request URLs that match a
     * location and passes the rest through.
     *
     * @throws LogicException for a name that is not a capability with a location
     */
    public function requestMiddleware(Graph $graph, ?string $capability = null): AgentRequestMiddleware
    {
        $bound = null;
        if ($capability !== null) {
            $bound = $this->capabilities->find($capability);
            if ($bound === null || $bound->location === null) {
                throw new LogicException(sprintf('"%s" is not a capability with a location.', $capability));
            }
        }

        return new AgentRequestMiddleware($this->capabilities, $graph->get(AgentAuthenticator::class), $graph->get(Executor::class), $graph->get(Problems::class), $bound);
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        self::catalog($graph);
        OAuthPlugin::of($graph);

        // An erased user or organization leaves no agent or host behind; a member who leaves takes the
        // organization's agents and hosts they registered with them (the agents revoked and sealed).
        return [static function (object $event) use ($graph): void {
            if ($event instanceof UserDeleted) {
                $graph->get(Agents::class)->deleteForUser($event->userId);
                $graph->get(Hosts::class)->deleteForUser($event->userId);
            }
            if ($event instanceof OrganizationDeleted) {
                $graph->get(Agents::class)->deleteForOrganization($event->organizationId);
                $graph->get(Hosts::class)->deleteForOrganization($event->organizationId);
            }
            if ($event instanceof MemberRemoved) {
                foreach ($graph->get(Agents::class)->revokeForMember($event->organizationId, $event->userId) as $agent) {
                    $graph->events()->dispatch(AgentEvent::bySystem(AuditNames::REVOKED, $agent->id, $agent->subject(), $agent->organizationId, ['how' => 'member_removed']));
                }
                $graph->get(Hosts::class)->revokeForMember($event->organizationId, $event->userId);
            }
        }];
    }

    /**
     * One MCP tool per capability the calling agent holds a live grant for, `agents.<capability>`; a
     * call is an execution with its receipt. Nothing for a principal that is not an agent.
     */
    #[Override]
    public function mcpTools(Graph $graph, ?TokenInterface $principal): array
    {
        if ($principal === null) {
            return [];
        }
        try {
            $agent = $graph->get(AgentAuthenticator::class)->fromToken($principal);
        } catch (AgentException) {
            return [];
        }
        if ($agent === null) {
            return [];
        }
        $executor = $graph->get(Executor::class);
        $tools = [];
        foreach ($graph->get(Grants::class)->live($agent->agent) as $grant) {
            $capability = $this->capabilities->find($grant->capability);
            if ($capability === null || $capability->handler === null) {
                continue;
            }
            $tools[] = new Tool(
                'agents.' . $capability->name,
                $capability->description,
                $capability->input,
                static function (array $arguments) use ($executor, $agent, $capability): array {
                    try {
                        return ['status' => 200, 'body' => $executor->execute($agent, $capability->name, $arguments)->toArray()];
                    } catch (AgentException $exception) {
                        return ['status' => $exception->status, 'body' => $exception->toProblem()];
                    }
                },
                null,
                false,
                $capability->risk === Settings::RISK_HIGH,
            );
        }

        return $tools;
    }

    /**
     * The `agent.*` names join the audit catalog: the audit plugin must be registered.
     */
    public static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend(AuditNames::ALL);

        return $catalog;
    }

    private function discovery(Graph $graph): Discovery
    {
        $oauth = OAuthPlugin::of($graph);
        $mcp = isset($graph->plugins()[self::MCP_PLUGIN]) ? $oauth->baseUrl() . '/mcp' : null;

        return new Discovery($this->settings, $graph->config()->auth->issuer, $oauth->baseUrl() . '/oauth2/token', $mcp);
    }
}

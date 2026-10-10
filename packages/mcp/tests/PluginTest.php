<?php

declare(strict_types=1);

namespace Polaris\Mcp\Tests;

use DateTimeImmutable;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use LogicException;
use Override;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Keys;
use Polaris\Admin\Principal\Role;
use Polaris\Anonymous\AnonymousPlugin;
use Polaris\ApiKeys\ApiKeysPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Authorization\Gate;
use Polaris\Authorization\PermissionCatalogSeeder;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\Plugin;
use Polaris\Contract\TokenInterface;
use Polaris\Mcp\Console\McpCommand;
use Polaris\Mcp\Http\McpRequestMiddleware;
use Polaris\Mcp\McpPlugin;
use Polaris\Mcp\McpResolver;
use Polaris\Mcp\Principal;
use Polaris\Mcp\Principals;
use Polaris\Mcp\Protect\McpProtectedResource;
use Polaris\Mcp\Server\CliTools;
use Polaris\Mcp\Server\Dispatcher;
use Polaris\Mcp\Server\ManifestTools;
use Polaris\Mcp\Server\McpServer;
use Polaris\Mcp\Server\Resources;
use Polaris\Mcp\Server\ToolHandler;
use Polaris\Mcp\Server\ToolSchema;
use Polaris\Mcp\Tool;
use Polaris\Mcp\ToolProvider;
use Polaris\Mcp\Transport\Http;
use Polaris\Mcp\Transport\Stdio;
use Polaris\Model\User;
use Polaris\MultiSession\MultiSessionPlugin;
use Polaris\OAuth\OAuthPlugin;
use Polaris\Passkey\PasskeyPlugin;
use Polaris\Passwordless\PasswordlessPlugin;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Polaris;
use Polaris\Scim\ScimPlugin;
use Polaris\Sentinel\SentinelPlugin;
use Polaris\Social\SocialPlugin;
use Polaris\Sso\SsoPlugin;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\Token;
use Polaris\Username\UsernamePlugin;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Uid\Uuid;

use function array_column;
use function array_map;
use function array_unique;
use function count;
use function file_get_contents;
use function fopen;
use function fwrite;
use function in_array;
use function json_decode;
use function json_encode;
use function rewind;
use function str_repeat;
use function sys_get_temp_dir;
use function tempnam;

/**
 * The plugin wired through `Polaris::create()`; tool names unique over the whole repository's manifest;
 * the schemas folded from the OpenAPI operations; the tools listed per principal; `bin/polaris mcp`
 * over memory streams (WP4 acceptance 2: one tool per endpoint the principal may call, with JSON
 * Schemas from the manifest). Separate processes: the schema registry is static.
 */
#[CoversClass(McpPlugin::class)]
#[CoversClass(McpResolver::class)]
#[CoversClass(McpRequestMiddleware::class)]
#[CoversClass(Principal::class)]
#[CoversClass(Principals::class)]
#[CoversClass(ToolSchema::class)]
#[CoversClass(ManifestTools::class)]
#[CoversClass(Dispatcher::class)]
#[CoversClass(CliTools::class)]
#[CoversClass(Resources::class)]
#[CoversClass(ToolHandler::class)]
#[CoversClass(McpServer::class)]
#[CoversClass(Stdio::class)]
#[CoversClass(Http::class)]
#[CoversClass(McpCommand::class)]
#[CoversClass(Tool::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string BASE = 'https://auth.polaris.test';

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $graph = $this->graph();
        $plugin = McpPlugin::of($graph);
        self::assertSame('mcp', $plugin->id());
        self::assertSame(self::BASE . '/mcp', $plugin->resource());
        self::assertSame(self::BASE . '/.well-known/oauth-protected-resource/mcp', $plugin->metadataUrl());
        self::assertSame([], $plugin->schema(), 'no tables');
        self::assertNotNull($graph->manifest()->find('POST', '/mcp'));
        self::assertNotNull($graph->manifest()->find('GET', '/.well-known/oauth-protected-resource/mcp'));
        self::assertInstanceOf(McpProtectedResource::class, $graph->get(McpProtectedResource::class));
        self::assertSame(self::BASE . '/mcp', $graph->get(McpProtectedResource::class)->metadata()['resource']);
        self::assertSame([self::BASE], $graph->get(McpProtectedResource::class)->metadata()['authorization_servers']);
        self::assertContains('org.read', $graph->get(McpProtectedResource::class)->metadata()['scopes_supported']);
        self::assertInstanceOf(McpServer::class, $graph->get(McpServer::class));
        self::assertInstanceOf(Http::class, $graph->get(Http::class));
        self::assertInstanceOf(McpRequestMiddleware::class, $plugin->middleware($graph)[0]);
        self::assertSame('mcp', $plugin->commands($graph)[0]->getName());

        // The bearer resolver answers the principal attribute and nothing on the wire.
        $resolver = $plugin->bearerResolvers($graph)[0];
        self::assertInstanceOf(McpResolver::class, $resolver);
        $token = new Token('t', ['sub' => 'ada']);
        $request = (new ServerRequestFactory())->createServerRequest('GET', self::BASE . '/auth/me')->withHeader('Authorization', 'Bearer x');
        self::assertNull($resolver->resolve($request));
        self::assertSame($token, $resolver->resolve($request->withAttribute(McpPlugin::PRINCIPAL, $token)));

        $this->expectException(LogicException::class);
        new McpPlugin('auth.polaris.test', new ServerRequestFactory(), new ResponseFactory(), new StreamFactory());
    }

    public function testToolNamesAreUniqueOverEveryPluginOfTheRepository(): void
    {
        $graph = $this->graph([
            new AuditPlugin(),
            new AdminPlugin(),
            new SentinelPlugin(),
            new SsoPlugin(self::BASE),
            new ScimPlugin(self::BASE),
            new PasswordlessPlugin(self::BASE),
            new UsernamePlugin(),
            new AnonymousPlugin(),
            new MultiSessionPlugin(),
            new PasskeyPlugin(['https://app.polaris.test']),
            new SocialPlugin(self::BASE, ['github' => ['client_id' => 'gh', 'client_secret' => 'secret']]),
            new ApiKeysPlugin(),
            new OAuthPlugin(self::BASE, audiences: [self::BASE . '/mcp']),
        ]);
        $tools = $graph->get(ManifestTools::class)->all();
        $names = array_map(static fn(Tool $tool): string => $tool->name, $tools);
        self::assertSame(count($names), count(array_unique($names)), 'every tool name is unique');
        self::assertCount(count($graph->manifest()->endpoints()) - 2, $tools, 'one tool per route but the mcp plugin\'s own two');
        foreach (['polaris.auth.me', 'polaris.orgs.members.list', 'polaris.admin.users.ban', 'polaris.oauth.token', 'polaris.scim.users.list', 'polaris.auth.mfa.totp.enroll'] as $name) {
            self::assertContains($name, $names);
        }
        self::assertNotContains('polaris.mcp.mcp', $names);
        foreach ($names as $name) {
            self::assertMatchesRegularExpression('/^polaris(\.[a-z0-9]+)+$/', $name);
        }
    }

    public function testSchemasFoldTheOpenApiOperation(): void
    {
        $graph = $this->graph([new AuditPlugin(), new AdminPlugin()]);
        $schema = new ToolSchema($graph->manifest());
        $byName = [];
        foreach ($graph->manifest()->endpoints() as $spec) {
            $byName[ToolSchema::name($spec)] = $spec;
        }

        // A body route: the body's properties and required list.
        $login = $schema->input($byName['polaris.auth.login']);
        self::assertSame('object', $login['type']);
        self::assertSame(['type' => 'string', 'format' => 'email', 'maxLength' => 320], $login['properties']['email']);
        self::assertSame('password', $login['properties']['password']['format']);
        self::assertContains('email', $login['required']);
        self::assertContains('password', $login['required']);
        self::assertSame('Authenticate with email and password (POST /auth/login)', ToolSchema::description($byName['polaris.auth.login']));

        // A path + query route: the path parameter required, the query fields typed.
        $audit = $schema->input($byName['polaris.audit.organization']);
        self::assertSame(['type' => 'string', 'description' => 'path parameter'], $audit['properties']['id']);
        self::assertSame(['type' => 'integer', 'description' => 'query parameter'], $audit['properties']['limit']);
        self::assertSame(['id'], $audit['required']);

        // A path route: the path parameter alone; no parameters at all: an empty object.
        self::assertSame(['id'], $schema->input($byName['polaris.orgs.members.list'])['required']);
        self::assertSame(['type' => 'object', 'properties' => []], $schema->input($byName['polaris.auth.me']));

        // The output: {status, body} with the body typed from the example.
        $output = $schema->output($byName['polaris.auth.me']);
        self::assertSame(['status', 'body'], $output['required']);
        self::assertSame('integer', $output['properties']['status']['type']);
        self::assertSame(['type' => 'string'], $output['properties']['body']['properties']['data']['properties']['email']);

        // Annotations from the effect.
        $tools = $graph->get(ManifestTools::class)->all();
        $byTool = array_column(array_map(static fn(Tool $t): array => ['n' => $t->name, 't' => $t], $tools), 't', 'n');
        self::assertTrue($byTool['polaris.auth.me']->readOnly);
        self::assertFalse($byTool['polaris.auth.me']->destructive);
        self::assertTrue($byTool['polaris.orgs.delete']->destructive);
        self::assertFalse($byTool['polaris.orgs.delete']->readOnly);
    }

    public function testToolsAreListedPerPrincipal(): void
    {
        $graph = $this->graph([new AuditPlugin(), new AdminPlugin(), new ApiKeysPlugin(), $this->toolProvider()]);
        $this->seed($graph);
        $user = $this->user($graph);
        $org = $graph->organizations()->create('Acme', null, $user->id);
        $tools = $graph->get(ManifestTools::class);
        $names = static fn(Principal $principal): array => array_map(static fn(Tool $tool): string => $tool->name, $tools->for($principal));

        $anonymous = $names(Principal::anonymous());
        self::assertContains('polaris.auth.login', $anonymous);
        self::assertContains('stub.echo', $anonymous, 'a ToolProvider plugin adds its tools');
        foreach (['polaris.auth.me', 'polaris.auth.mfa.login.verify', 'polaris.admin.users.list', 'polaris.orgs.create'] as $hidden) {
            self::assertNotContains($hidden, $anonymous);
        }

        $owner = $names(new Principal(new Token('t', ['sub' => $user->id, 'org' => $org->id])));
        foreach (['polaris.auth.login', 'polaris.auth.me', 'polaris.orgs.create', 'polaris.orgs.members.list', 'polaris.orgs.update', 'polaris.auth.mfa.totp.enroll'] as $allowed) {
            self::assertContains($allowed, $owner, $allowed);
        }
        self::assertNotContains('polaris.admin.users.list', $owner, 'not an operator');
        self::assertNotContains('polaris.auth.mfa.login.verify', $owner, 'never an mfa_token route');
        self::assertNotContains('polaris.users.disable', $owner, 'users.manage is not the owner\'s');

        $delegated = $names(new Principal(new Token('t', ['sub' => $user->id, 'org' => $org->id, Gate::DELEGATED => ['members.read']])));
        self::assertContains('polaris.auth.me', $delegated);
        self::assertContains('polaris.orgs.members.list', $delegated);
        self::assertNotContains('polaris.orgs.update', $delegated, 'org.update was not delegated');
        self::assertNotContains('polaris.orgs.create', $delegated, 'a permissionless write');
        self::assertNotContains('polaris.auth.mfa.totp.enroll', $delegated, 'a step-up route');

        $key = $graph->get(Keys::class)->create('ops', Role::Admin)->plaintext;
        $operator = $graph->get(Principals::class)->fromCredential($key);
        self::assertTrue($operator->operator);
        self::assertNull($operator->token);
        $operatorTools = $names($operator);
        self::assertContains('polaris.admin.users.list', $operatorTools);
        self::assertContains('polaris.auth.login', $operatorTools);
        self::assertNotContains('polaris.auth.me', $operatorTools, 'a key is nobody\'s session');

        $session = $graph->tokens()->mint(new SessionPrincipal($user->id, $org->id));
        $principal = $graph->get(Principals::class)->fromCredential($session);
        self::assertInstanceOf(TokenInterface::class, $principal->token);
        self::assertFalse($principal->operator);
        self::assertSame($user->id, $principal->token->getMetadata('sub'));
        self::assertTrue($graph->get(Principals::class)->fromCredential(null)->token === null);
        $this->expectExceptionMessage('does not authenticate');
        $graph->get(Principals::class)->fromCredential('garbage');
    }

    public function testTheStdioCommandServesTheToolsOfThePrincipal(): void
    {
        $graph = $this->graph([new AuditPlugin(), new AdminPlugin()]);
        $this->seed($graph);
        $key = $graph->get(Keys::class)->create('ops', Role::Admin)->plaintext;
        $meta = ['_meta' => ['io.modelcontextprotocol/protocolVersion' => '2025-11-25', 'io.modelcontextprotocol/clientCapabilities' => new \stdClass()]];
        $responses = $this->stdio($graph, $key, [
            ['jsonrpc' => '2.0', 'id' => 0, 'method' => 'initialize', 'params' => ['protocolVersion' => '2025-11-25', 'capabilities' => new \stdClass(), 'clientInfo' => ['name' => 'test', 'version' => '1']]],
            ['jsonrpc' => '2.0', 'method' => 'notifications/initialized'],
            ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list', 'params' => $meta],
            ['jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/call', 'params' => ['name' => 'polaris.schema.export', 'arguments' => ['target' => 'sql:sqlite'], ...$meta]],
            ['jsonrpc' => '2.0', 'id' => 3, 'method' => 'tools/call', 'params' => ['name' => 'polaris.admin.users.list', 'arguments' => ['limit' => 10], ...$meta]],
            ['jsonrpc' => '2.0', 'id' => 4, 'method' => 'tools/call', 'params' => ['name' => 'polaris.auth.login', 'arguments' => ['email' => 'nobody@example.com', 'password' => 'wrong'], ...$meta]],
            ['jsonrpc' => '2.0', 'id' => 5, 'method' => 'resources/read', 'params' => ['uri' => 'polaris://manifest', ...$meta]],
            ['jsonrpc' => '2.0', 'id' => 6, 'method' => 'resources/templates/list', 'params' => $meta],
        ]);
        self::assertSame('Polaris', $responses[0]['result']['serverInfo']['name']);

        $tools = $responses[1]['result']['tools'];
        $names = array_column($tools, 'name');
        $public = count($graph->get(ManifestTools::class)->for(Principal::anonymous()));
        $admin = 0;
        foreach ($graph->manifest()->endpoints() as $spec) {
            $admin += in_array('admin', $spec->tags, true) ? 1 : 0;
        }
        self::assertCount($public + $admin + count(CliTools::COMMANDS), $tools, 'the public routes, the admin routes, the CLI commands');
        foreach (['polaris.schema.export', 'polaris.schema.diff', 'polaris.manifest', 'polaris.doctor', 'polaris.admin.users.list', 'polaris.auth.login'] as $name) {
            self::assertContains($name, $names);
        }
        self::assertNotContains('polaris.auth.me', $names);
        $login = $tools[array_search('polaris.auth.login', $names, true)];
        self::assertSame(['email', 'password'], $login['inputSchema']['required']);
        self::assertSame(['status', 'body'], $login['outputSchema']['required']);
        self::assertFalse($login['annotations']['readOnlyHint']);

        self::assertFalse($responses[2]['result']['isError']);
        self::assertStringContainsString('CREATE TABLE "auth_users"', $responses[2]['result']['content'][0]['text']);
        self::assertSame(200, $responses[2]['result']['structuredContent']['status']);

        self::assertFalse($responses[3]['result']['isError'], json_encode($responses[3]));
        self::assertSame(['data' => [], 'next_cursor' => null], $responses[3]['result']['structuredContent']['body']);

        self::assertTrue($responses[4]['result']['isError']);
        self::assertSame(['status' => 401, 'body' => ['error' => 'invalid_credentials', 'message' => 'Invalid email or password.']], $responses[4]['result']['structuredContent']);

        self::assertSame('application/json', $responses[5]['result']['contents'][0]['mimeType']);
        self::assertSame('3.1.0', json_decode($responses[5]['result']['contents'][0]['text'], true)['openapi']);
        self::assertSame(Resources::PROBLEMS, $responses[6]['result']['resourceTemplates'][0]['uriTemplate']);

        // A credential nothing accepts stops the command before it serves.
        $tester = new CommandTester(McpPlugin::of($graph)->commands($graph)[0]);
        self::assertSame(1, $tester->execute(['--token' => 'garbage']));
        self::assertStringContainsString('does not authenticate', $tester->getDisplay());
    }

    public function testTheHttpTransportServesEitherEra(): void
    {
        $meta = ['_meta' => ['io.modelcontextprotocol/protocolVersion' => '2026-07-28', 'io.modelcontextprotocol/clientCapabilities' => new \stdClass()]];
        $post = static function (array $body, array $headers): \Psr\Http\Message\ServerRequestInterface {
            $request = (new ServerRequestFactory())->createServerRequest('POST', self::BASE . '/mcp')->withHeader('Content-Type', 'application/json')->withHeader('Accept', 'application/json');
            foreach ($headers as $name => $value) {
                $request = $request->withHeader($name, $value);
            }
            $request->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR));
            $request->getBody()->rewind();

            return $request;
        };

        // The default: the stateless profile, one request at a time, nothing kept.
        $graph = $this->graph();
        $builder = static fn(Graph $graph) => $graph->get(McpServer::class)->builder(Principal::anonymous());
        $listed = $graph->get(Http::class)->handle($builder($graph), $post(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list', 'params' => $meta], ['MCP-Protocol-Version' => '2026-07-28', 'Mcp-Method' => 'tools/list']));
        self::assertSame(200, $listed->getStatusCode(), (string) $listed->getBody());
        self::assertContains('polaris.auth.login', array_column(json_decode((string) $listed->getBody(), true)['result']['tools'], 'name'));
        $handshake = $graph->get(Http::class)->handle($builder($graph), $post(['jsonrpc' => '2.0', 'id' => 0, 'method' => 'initialize', 'params' => ['protocolVersion' => '2025-11-25', 'capabilities' => new \stdClass(), 'clientInfo' => ['name' => 't', 'version' => '1']]], []));
        self::assertSame(400, $handshake->getStatusCode(), 'the handshake era is not served');

        // Allowed: the 2025 handshake opens a session in the cache that the next request names.
        $keys = TestKeys::rsa();
        $graph = Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => self::BASE]),
            database: new InMemoryAdapter(),
            plugins: [new McpPlugin(self::BASE, new ServerRequestFactory(), new ResponseFactory(), new StreamFactory(), legacy: 'allow')],
        ))->graph();
        $opened = $graph->get(Http::class)->handle($builder($graph), $post(['jsonrpc' => '2.0', 'id' => 0, 'method' => 'initialize', 'params' => ['protocolVersion' => '2025-11-25', 'capabilities' => new \stdClass(), 'clientInfo' => ['name' => 't', 'version' => '1']]], []));
        self::assertSame(200, $opened->getStatusCode(), (string) $opened->getBody());
        $session = $opened->getHeaderLine('Mcp-Session-Id');
        self::assertNotSame('', $session);
        self::assertSame('Polaris', json_decode((string) $opened->getBody(), true)['result']['serverInfo']['name']);
        $graph->get(Http::class)->handle($builder($graph), $post(['jsonrpc' => '2.0', 'method' => 'notifications/initialized'], ['Mcp-Session-Id' => $session]));
        $listed = $graph->get(Http::class)->handle($builder($graph), $post(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list', 'params' => []], ['Mcp-Session-Id' => $session, 'MCP-Protocol-Version' => '2025-11-25']));
        self::assertSame(200, $listed->getStatusCode(), (string) $listed->getBody());
        self::assertContains('polaris.auth.login', array_column(json_decode((string) $listed->getBody(), true)['result']['tools'], 'name'));
        // The modern profile is served on the same endpoint.
        $modern = $graph->get(Http::class)->handle($builder($graph), $post(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list', 'params' => $meta], ['MCP-Protocol-Version' => '2026-07-28', 'Mcp-Method' => 'tools/list']));
        self::assertSame(200, $modern->getStatusCode(), (string) $modern->getBody());
    }

    /**
     * @param list<array<string, mixed>> $messages
     * @return list<array<string, mixed>>
     */
    private function stdio(Graph $graph, string $token, array $messages): array
    {
        $command = McpPlugin::of($graph)->commands($graph)[0];
        self::assertInstanceOf(McpCommand::class, $command);
        $input = fopen('php://memory', 'w+');
        $path = (string) tempnam(sys_get_temp_dir(), 'mcp');
        $output = fopen($path, 'w+');
        self::assertIsResource($input);
        self::assertIsResource($output);
        foreach ($messages as $message) {
            fwrite($input, json_encode($message, JSON_THROW_ON_ERROR) . "\n");
        }
        rewind($input);
        self::assertSame(0, (new CommandTester($command->withStreams($input, $output)))->execute(['--token' => $token]));
        $responses = [];
        foreach (explode("\n", (string) file_get_contents($path)) as $line) {
            if ($line !== '') {
                $responses[] = (array) json_decode($line, true, flags: JSON_THROW_ON_ERROR);
            }
        }

        return $responses;
    }

    /**
     * @param list<Plugin> $plugins
     */
    private function graph(array $plugins = []): Graph
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => self::BASE]),
            database: new InMemoryAdapter(),
            plugins: [...$plugins, new McpPlugin(self::BASE, new ServerRequestFactory(), new ResponseFactory(), new StreamFactory())],
        ))->graph();
    }

    private function seed(Graph $graph): void
    {
        (new PermissionCatalogSeeder($graph->permissionCatalog()))->seed($graph->database(), $graph->clock()->now());
    }

    private function user(Graph $graph): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = 'ada@example.com';
        $user->emailVerifiedAt = new DateTimeImmutable();
        $user->createdAt = new DateTimeImmutable();
        $user->updatedAt = new DateTimeImmutable();
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    private function toolProvider(): Plugin
    {
        return new class extends AbstractPlugin implements ToolProvider {
            #[Override]
            public function id(): string
            {
                return 'stub';
            }

            #[Override]
            public function mcpTools(Graph $graph, ?TokenInterface $principal): array
            {
                return [new Tool('stub.echo', 'Echo', ['type' => 'object', 'properties' => []], static fn(array $a): array => ['status' => 200, 'body' => $a])];
            }
        };
    }
}

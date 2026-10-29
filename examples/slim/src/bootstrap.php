<?php

declare(strict_types=1);

use Polaris\Admin\AdminPlugin;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\Capability;
use Polaris\Audit\AuditPlugin;
use Polaris\Mcp\McpPlugin;
use Polaris\OAuth\OAuthPlugin;
use Polaris\Passkey\PasskeyPlugin;
use Polaris\Config\EnvironmentConfig;
use Polaris\Pdo\PdoAdapter;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Social\SocialPlugin;
use Polaris\Support\CacheRateStore;
use Polaris\Support\InMemoryCache;
use Polaris\Support\SystemClock;
use Polaris\Wiring\Config;
use PolarisDemo\Dispatcher;
use PolarisDemo\Env;
use PolarisDemo\FakeProvider;
use PolarisDemo\FileCache;
use PolarisDemo\LoopbackClient;
use PolarisDemo\FileMailer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Factory\AppFactory;
use Slim\Psr7\Factory\RequestFactory;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Factory\StreamFactory;

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';

Env::load($root);

$dsn = Env::require('POLARIS_DSN');
$pdo = new PDO(str_starts_with($dsn, 'sqlite:') ? 'sqlite:' . Env::sqlitePath($root, $dsn) : $dsn);
$pdo->exec('PRAGMA foreign_keys = ON');

$dispatcher = new Dispatcher();
// localhost, not 127.0.0.1: a passkey's relying party id must be a domain.
$baseUrl = rtrim((string) (getenv('POLARIS_BASE_URL') ?: 'http://localhost:8080'), '/');
$app = AppFactory::create();
$app->addBodyParsingMiddleware();
// Behind a TLS-terminating proxy the request must carry its public https URI: cookie token delivery
// refuses plaintext and compares the Origin with it (docs/cookie-mode/spec.md §2.6). This is the host's
// trusted-proxy handling, opt-in here because php -S sees every local request from 127.0.0.1.
if (getenv('POLARIS_TRUST_FORWARDED_PROTO') === '1') {
    $app->add(static function (ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface {
        $proxied = ($request->getServerParams()['REMOTE_ADDR'] ?? null) === '127.0.0.1' && $request->getHeaderLine('X-Forwarded-Proto') === 'https';

        return $handler->handle($proxied ? $request->withUri($request->getUri()->withScheme('https')) : $request);
    });
}
// The demo's own OAuth 2 server and mailbox, outside Polaris's routes.
FakeProvider::register($app, $root);
$polaris = Polaris::create(new Config(
    secrets: EnvironmentConfig::secrets(),
    // POLARIS_TOKEN_DELIVERY=cookie: the refresh token in an HttpOnly cookie (needs https; see above).
    auth: EnvironmentConfig::auth(overrides: getenv('POLARIS_TOKEN_DELIVERY') === 'cookie' ? ['flows' => ['token_delivery' => 'cookie']] : []),
    database: new PdoAdapter($pdo),
    mailer: new FileMailer($root . '/var/mail.log'),
    // php -S runs every request in a fresh process: the plugins' short-lived state (OAuth states, passkey
    // challenges, hand-off codes) goes to files; the rate limits stay in memory, so the demo never locks itself out.
    cache: new FileCache($root . '/var/cache'),
    rateStore: new CacheRateStore(new InMemoryCache(), new SystemClock()),
    dispatcher: $dispatcher,
    plugins: [
        new AuditPlugin(),
        new AdminPlugin(),
        // Social sign-in through the fake provider (add real ones with their client ids and secrets).
        new SocialPlugin(
            baseUrl: $baseUrl,
            providers: ['fake' => ['client_id' => 'demo', 'client_secret' => 'demo', 'definition' => FakeProvider::definition($baseUrl)]],
            httpClient: new LoopbackClient($app),
            requestFactory: new RequestFactory(),
            streamFactory: new StreamFactory(),
            redirectUris: [$baseUrl . '/signed-in'],
        ),
        new PasskeyPlugin(origins: [$baseUrl], rpName: 'Polaris demo'),
        // The OAuth 2.1 provider: the consent and device pages are the reference HTML in public/; tokens
        // minted for the MCP resource (<base>/mcp) are accepted on every route.
        new OAuthPlugin(baseUrl: $baseUrl, consentUrl: $baseUrl . '/consent.html', deviceUrl: $baseUrl . '/device.html', audiences: [$baseUrl . '/mcp']),
        // Polaris as an MCP server on POST /mcp: a tool per route the token's principal may call.
        new McpPlugin($baseUrl, new ServerRequestFactory(), new ResponseFactory(), new StreamFactory(), serverName: 'Polaris demo'),
        // Agents: one low-risk capability, auto-approved for an owner who holds members.read, echoing its arguments;
        // public/approve.html is where a person decides the approvals the policy does not.
        new AgentsPlugin(
            baseUrl: $baseUrl,
            capabilities: [new Capability(
                name: 'demo.echo',
                description: 'Echo the arguments back',
                input: ['type' => 'object', 'properties' => ['message' => ['type' => 'string']], 'additionalProperties' => false],
                permission: 'members.read',
                risk: 'low',
                handler: static fn(array $arguments): array => ['echo' => $arguments],
            )],
            approvalUrl: $baseUrl . '/approve.html',
            providerName: 'Polaris demo',
            description: 'The Slim demo of Polaris for PHP',
            responses: new ResponseFactory(),
        ),
    ],
));
foreach ($polaris->listeners() as $listener) {
    $dispatcher->listen($listener);
}
$pipeline = new Pipeline($polaris->graph(), new ResponseFactory());
// Polaris's stack runs on its own routes only (the fake provider's static routes match first). Slim
// runs the last-added middleware first; Polaris lists its stack in execution order.
$route = $app->any('/{path:.*}', static fn(ServerRequestInterface $request): ResponseInterface => $pipeline->handler()->handle($request));
foreach (array_reverse($pipeline->middleware()) as $middleware) {
    $route->add($middleware);
}

return $app;

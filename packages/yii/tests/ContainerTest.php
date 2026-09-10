<?php

declare(strict_types=1);

namespace Polaris\Yii\Tests;

use HttpSoft\Message\ServerRequestFactory;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\Dialect;
use Polaris\Event\UserLoggedIn;
use Polaris\Mfa\LogOtpMailer;
use Polaris\Mfa\LogSmsSender;
use Polaris\Pdo\PdoAdapter;
use Polaris\Pdo\SchemaInstaller;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Yii\Event\Events;
use Polaris\Yii\Event\PolarisListener;
use Polaris\Yii\Factory;
use Polaris\Yii\Http\PolarisController;
use Polaris\Wiring\Graph;
use Psr\EventDispatcher\EventDispatcherInterface;
use Yiisoft\Router\RouteCollectionInterface;

use function array_filter;
use function array_keys;
use function json_decode;
use function str_starts_with;

#[CoversClass(Factory::class)]
#[CoversClass(PolarisController::class)]
#[CoversClass(Events::class)]
#[CoversClass(PolarisListener::class)]
final class ContainerTest extends TestCase
{
    public function testBuildsTheGraphFromTheParamsAndTheApplicationServices(): void
    {
        $container = YiiApp::container([
            'path_prefix' => '/api/auth',
            'secrets' => Fixtures::secretsArray(),
            'auth' => ['issuer' => 'https://issuer.test', 'access_token' => ['denylist' => true]],
            'rate_limits' => ['login' => ['limit' => 3]],
            'database' => ['dsn' => 'sqlite::memory:'],
        ]);

        $graph = $container->get(Graph::class);
        self::assertSame('https://issuer.test', $graph->config()->auth->issuer);
        self::assertTrue($graph->config()->auth->accessToken->denylist);
        self::assertSame(3, $graph->rateLimits()->login->limit);
        self::assertSame('test', $graph->config()->secrets->jwtKid);
        self::assertInstanceOf(PdoAdapter::class, $graph->database());
        self::assertSame(Dialect::Sqlite, $graph->database()->dialect());
        self::assertSame($container->get(EventDispatcherInterface::class), $graph->events());
        self::assertInstanceOf(LogOtpMailer::class, $graph->mailer());
        self::assertInstanceOf(LogSmsSender::class, $graph->sms());
        self::assertSame('/api/auth', $graph->config()->pathPrefix);
        self::assertSame($container->get(PDO::class), Factory::connection($container));

        $routes = $container->get(RouteCollectionInterface::class)->getRoutes();
        self::assertCount(52, array_filter(array_keys($routes), static fn (string $name): bool => str_starts_with($name, 'polaris.')));
        self::assertSame('/api/auth/auth/login', $routes['polaris.auth.login']->getData('pattern'));
        self::assertSame(['POST'], $routes['polaris.auth.login']->getData('methods'));

        $response = YiiApp::handle($container, (new ServerRequestFactory())->createServerRequest('GET', '/api/auth/auth/.well-known/jwks.json'));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('test', json_decode((string) $response->getBody(), true)['keys'][0]['kid'] ?? null);
        self::assertSame(405, YiiApp::handle($container, (new ServerRequestFactory())->createServerRequest('GET', '/api/auth/auth/login'))->getStatusCode());
        self::assertSame(404, YiiApp::handle($container, (new ServerRequestFactory())->createServerRequest('GET', '/nope'))->getStatusCode());
    }

    public function testThePolarisListenersRunThroughYiisDispatcher(): void
    {
        $adapter = new InMemoryAdapter();
        $container = YiiApp::container(['secrets' => Fixtures::secretsArray(), 'auth' => ['issuer' => 'x']], [DatabaseAdapter::class => $adapter]);

        self::assertSame($adapter, $container->get(Graph::class)->database());
        self::assertCount(34, Events::listeners(), 'every class in Polaris\\Event except the null dispatcher');
        self::assertSame([PolarisListener::class], Events::listeners()[UserLoggedIn::class]);
        self::assertSame(0, $adapter->count('auth_audit_log', []));
        $container->get(EventDispatcherInterface::class)->dispatch(new UserLoggedIn('user-1', 'session-1'));
        self::assertSame(1, $adapter->count('auth_audit_log', []), 'the audit listener ran through yiisoft/yii-event');
    }

    public function testADatabaseIsRequired(): void
    {
        $container = YiiApp::container(['secrets' => Fixtures::secretsArray(), 'auth' => ['issuer' => 'x']]);

        $this->expectExceptionMessage('Polaris needs a database');
        $container->get(Graph::class);
    }

    public function testTheSchemaInstallerRunsOnTheContainersConnection(): void
    {
        $container = YiiApp::container(['secrets' => Fixtures::secretsArray(), 'auth' => ['issuer' => 'x'], 'database' => ['dsn' => 'sqlite::memory:']]);
        SchemaInstaller::create(Factory::connection($container));
        self::assertGreaterThan(0, $container->get(Graph::class)->database()->count('auth_permissions', []));
    }
}

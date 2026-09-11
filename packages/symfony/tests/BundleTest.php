<?php

declare(strict_types=1);

namespace Polaris\Symfony\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\Dialect;
use Polaris\Event\UserLoggedIn;
use Polaris\Mfa\LogOtpMailer;
use Polaris\Mfa\LogSmsSender;
use Polaris\Pdo\PdoAdapter;
use Polaris\Tests\Support\Plugin\SamplePlugin;
use Polaris\Polaris;
use Polaris\Symfony\Event\PolarisEventSubscriber;
use Polaris\Symfony\Factory;
use Polaris\Symfony\PolarisBundle;
use Polaris\Symfony\Routing\PolarisRouteLoader;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Wiring\Graph;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouterInterface;

use function array_filter;
use function array_keys;
use function count;
use function json_decode;
use function str_starts_with;

#[CoversClass(PolarisBundle::class)]
#[CoversClass(Factory::class)]
#[CoversClass(PolarisRouteLoader::class)]
#[CoversClass(PolarisEventSubscriber::class)]
final class BundleTest extends TestCase
{
    public function testBuildsTheGraphFromTheConfigurationAndTheApplicationServices(): void
    {
        $kernel = new TestKernel([
            'path_prefix' => '/api/auth',
            'secrets' => Fixtures::secretsArray(),
            'auth' => ['issuer' => 'https://issuer.test', 'access_token' => ['denylist' => true]],
            'rate_limits' => ['login' => ['limit' => 3]],
            'database' => ['dsn' => 'sqlite::memory:'],
        ]);
        $kernel->boot();
        $container = $kernel->getContainer();

        $graph = $container->get(Graph::class);
        self::assertInstanceOf(Graph::class, $graph);
        self::assertSame('https://issuer.test', $graph->config()->auth->issuer);
        self::assertTrue($graph->config()->auth->accessToken->denylist);
        self::assertSame(3, $graph->rateLimits()->login->limit);
        self::assertSame('test', $graph->config()->secrets->jwtKid);
        self::assertInstanceOf(PdoAdapter::class, $graph->database());
        self::assertSame(Dialect::Sqlite, $graph->database()->dialect());
        self::assertInstanceOf(Psr16Cache::class, $graph->cache());
        self::assertSame($container->get('event_dispatcher'), $graph->events());
        self::assertInstanceOf(LogOtpMailer::class, $graph->mailer());
        self::assertInstanceOf(LogSmsSender::class, $graph->sms());
        self::assertSame('/api/auth', $graph->config()->pathPrefix);

        $router = $container->get('router');
        self::assertInstanceOf(RouterInterface::class, $router);
        $routes = $router->getRouteCollection();
        $login = $routes->get('polaris.auth.login');
        self::assertInstanceOf(Route::class, $login);
        self::assertSame('/api/auth/auth/login', $login->getPath());
        self::assertSame(['POST'], $login->getMethods());
        self::assertSame('/api/auth/orgs/{id}/members/{userId}', $routes->get('polaris.orgs.member-remove')?->getPath());
        self::assertCount(52, array_filter(array_keys($routes->all()), static fn (string $name): bool => str_starts_with($name, 'polaris.')));

        $response = $kernel->handle(Request::create('/api/auth/auth/.well-known/jwks.json'));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->headers->get('Content-Type'));
        self::assertSame('test', json_decode((string) $response->getContent(), true)['keys'][0]['kid'] ?? null);
        // What HttpFoundation adds to every response, and what the contract harness ignores.
        self::assertSame('no-cache, private', $response->headers->get('Cache-Control'));
        self::assertSame(405, $kernel->handle(Request::create('/api/auth/auth/login', 'GET'))->getStatusCode());
        $kernel->shutdown();
    }

    public function testAPluginsRoutesAndServicesJoinTheBundle(): void
    {
        $kernel = new TestKernel([
            'secrets' => Fixtures::secretsArray(),
            'auth' => ['issuer' => 'https://issuer.test'],
            'database' => ['dsn' => 'sqlite::memory:'],
            'plugins' => ['polaris.test.plugin'],
        ], synthetic: ['polaris.test.plugin']);
        $kernel->boot();
        $kernel->getContainer()->set('polaris.test.plugin', new SamplePlugin());

        self::assertSame('/sample/notes', $kernel->getContainer()->get('router')->getRouteCollection()->get('polaris.sample.notes')?->getPath());
        $response = $kernel->handle(Request::create('/sample/notes'));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('hello', json_decode((string) $response->getContent(), true)['data'][0]['text'] ?? null);
        $problem = $kernel->handle(Request::create('/sample/notes?fail=1'));
        self::assertSame(403, $problem->getStatusCode());
        self::assertSame('application/problem+json', $problem->headers->get('Content-Type'));
        self::assertInstanceOf(SamplePlugin::class, $kernel->getContainer()->get(Polaris::class)->plugin('sample'));
        $kernel->shutdown();
    }

    public function testTheHostsServicesAndThePolarisListenersAreWired(): void
    {
        $adapter = new InMemoryAdapter();
        $kernel = new TestKernel([
            'secrets' => ['service' => 'polaris.test.secrets'],
            'auth' => ['service' => 'polaris.test.auth'],
            'database' => ['service' => 'polaris.test.database'],
        ], synthetic: ['polaris.test.secrets', 'polaris.test.auth', 'polaris.test.database']);
        $kernel->boot();
        $container = $kernel->getContainer();
        $container->set('polaris.test.secrets', Fixtures::secrets());
        $container->set('polaris.test.auth', Fixtures::auth());
        $container->set('polaris.test.database', $adapter);

        $graph = $container->get(Graph::class);
        self::assertInstanceOf(Graph::class, $graph);
        self::assertSame($adapter, $graph->database());

        self::assertCount(34, PolarisEventSubscriber::getSubscribedEvents(), 'every class in Polaris\\Event except the null dispatcher');
        self::assertArrayHasKey(UserLoggedIn::class, PolarisEventSubscriber::getSubscribedEvents());
        $dispatcher = $container->get('event_dispatcher');
        self::assertInstanceOf(EventDispatcherInterface::class, $dispatcher);
        self::assertSame(0, $adapter->count('auth_audit_log', []));
        $dispatcher->dispatch(new UserLoggedIn('user-1', 'session-1'));
        self::assertSame(1, $adapter->count('auth_audit_log', []), 'the audit listener ran through Symfony\'s dispatcher');
        $kernel->shutdown();
    }

    public function testADatabaseWithoutDsnOrServiceIsAConfigurationError(): void
    {
        $kernel = new TestKernel(['secrets' => Fixtures::secretsArray(), 'auth' => ['issuer' => 'x']]);

        $this->expectExceptionMessage('polaris.database needs a "dsn" or a "service".');
        $kernel->boot();
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Yii\Tests;

use HttpSoft\Message\ResponseFactory;
use HttpSoft\Message\ServerRequestFactory;
use HttpSoft\Message\StreamFactory;
use HttpSoft\Message\UploadedFileFactory;
use HttpSoft\Message\UriFactory;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\EventDispatcher\ListenerProviderInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Psr\Http\Message\UriFactoryInterface;
use ReflectionClass;
use Yiisoft\Di\Container;
use Yiisoft\Di\ContainerConfig;
use Yiisoft\Di\StateResetter;
use Yiisoft\EventDispatcher\Dispatcher\Dispatcher;
use Yiisoft\EventDispatcher\Provider\ListenerCollection;
use Yiisoft\EventDispatcher\Provider\Provider;
use Yiisoft\Middleware\Dispatcher\MiddlewareDispatcher;
use Yiisoft\Request\Body\RequestBodyParser;
use Yiisoft\Router\FastRoute\UrlMatcher;
use Yiisoft\Router\Middleware\Router;
use Yiisoft\Router\Route;
use Yiisoft\Router\RouteCollection;
use Yiisoft\Router\RouteCollectionInterface;
use Yiisoft\Router\RouteCollector;
use Yiisoft\Router\UrlMatcherInterface;
use Yiisoft\Yii\Event\ListenerCollectionFactory;
use Yiisoft\Yii\Http\Application;
use Yiisoft\Yii\Http\Handler\NotFoundHandler;

use function array_replace_recursive;
use function dirname;

/**
 * A Yii application for the tests: the package's `di.php` (and `di-console.php` for the console),
 * `routes.php` and `events-web.php`, plus what a Yii application provides itself (PSR-17 factories,
 * the route collection, the event dispatcher, the HTTP application on `RequestBodyParser` and the
 * router), plus the test's own definitions, which win.
 */
final class YiiApp
{
    /**
     * @param array<string, mixed> $polaris overrides of the `polaris` params
     * @param array<string, mixed> $definitions the test's definitions (instances allowed), merged last
     * @param list<Route> $routes the application's own routes, added to the Polaris routes
     */
    public static function container(array $polaris = [], array $definitions = [], array $routes = [], bool $console = false): Container
    {
        $config = dirname(__DIR__) . '/config';
        $params = array_replace_recursive(require $config . '/params.php', ['polaris' => $polaris]);
        $load = static function (string $file) use ($params): array {
            return (static function (string $file, array $params): array {
                return require $file;
            })($file, $params);
        };
        $polarisRoutes = $load($config . '/routes.php');
        $events = $load($config . '/events-web.php');

        $application = [
            ResponseFactoryInterface::class => ResponseFactory::class,
            ServerRequestFactoryInterface::class => ServerRequestFactory::class,
            StreamFactoryInterface::class => StreamFactory::class,
            UriFactoryInterface::class => UriFactory::class,
            UploadedFileFactoryInterface::class => UploadedFileFactory::class,
            // yiisoft/router's own config (merged by the config plugin in a real application): the route
            // collector, and the current route reset by the container's state resetter between requests.
            ...$load(dirname((string) (new ReflectionClass(Route::class))->getFileName(), 2) . '/config/di.php'),
            RouteCollectionInterface::class => static function (RouteCollector $collector) use ($polarisRoutes, $routes): RouteCollectionInterface {
                $collector->addRoute(...$polarisRoutes, ...$routes);

                return new RouteCollection($collector);
            },
            UrlMatcherInterface::class => static fn (RouteCollectionInterface $collection): UrlMatcher => new UrlMatcher($collection),
            ListenerCollection::class => static fn (ListenerCollectionFactory $factory): ListenerCollection => $factory->create($events),
            ListenerProviderInterface::class => Provider::class,
            EventDispatcherInterface::class => Dispatcher::class,
            Application::class => static fn (MiddlewareDispatcher $dispatcher, ResponseFactoryInterface $responses): Application => new Application(
                $dispatcher->withMiddlewares([RequestBodyParser::class, Router::class]),
                null,
                new NotFoundHandler($responses),
            ),
        ];

        return new Container(ContainerConfig::create()->withDefinitions([
            ...$load($config . '/di.php'),
            ...($console ? $load($config . '/di-console.php') : []),
            ...$application,
            ...$definitions,
        ]));
    }

    /**
     * One request through the application, then the per-request state reset a long-running Yii host
     * performs between requests.
     */
    public static function handle(Container $container, ServerRequestInterface $request): ResponseInterface
    {
        try {
            return $container->get(Application::class)->handle($request);
        } finally {
            $container->get(StateResetter::class)->reset();
        }
    }
}

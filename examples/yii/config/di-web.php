<?php

declare(strict_types=1);

use Psr\Http\Message\ResponseFactoryInterface;
use Yiisoft\Config\ConfigInterface;
use Yiisoft\Middleware\Dispatcher\MiddlewareDispatcher;
use Yiisoft\Router\RouteCollection;
use Yiisoft\Router\RouteCollectionInterface;
use Yiisoft\Router\RouteCollector;
use Yiisoft\Yii\Http\Application;
use Yiisoft\Yii\Http\Handler\NotFoundHandler;

/** @var array $params */

return [
    // The routes group: the 52 Polaris routes from the package plus config/routes.php.
    RouteCollectionInterface::class => static function (RouteCollector $collector, ConfigInterface $config): RouteCollectionInterface {
        $collector->addRoute(...$config->get('routes'));

        return new RouteCollection($collector);
    },
    Application::class => static fn (MiddlewareDispatcher $dispatcher, ResponseFactoryInterface $responses): Application => new Application(
        $dispatcher->withMiddlewares($params['middlewares']),
        null,
        new NotFoundHandler($responses),
    ),
];

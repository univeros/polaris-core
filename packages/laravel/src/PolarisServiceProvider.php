<?php

declare(strict_types=1);

namespace Polaris\Laravel;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as LaravelApplication;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Nyholm\Psr7\Factory\Psr17Factory;
use Polaris\Http\Manifest\Loader;
use Polaris\Laravel\Auth\PolarisGuard;
use Polaris\Laravel\Console\CliCommands;
use Polaris\Laravel\Console\InstallCommand;
use Polaris\Laravel\Http\PolarisController;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Wiring\Graph;

use function is_string;
use function rtrim;
use function str_replace;
use function substr;

/**
 * Registers Polaris in a Laravel application: `Polaris`, `Graph` and `Pipeline` as singletons built
 * from config/polaris.php, one route per manifest endpoint under `path_prefix`, the `polaris` guard,
 * the artisan commands and the mail views.
 */
final class PolarisServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/polaris.php', 'polaris');
        $this->app->singleton(Polaris::class, static fn (Application $app): Polaris => (new PolarisFactory($app))->create((array) $app->make(Repository::class)->get('polaris', [])));
        $this->app->singleton(Graph::class, static fn (Application $app): Graph => $app->make(Polaris::class)->graph());
        $this->app->singleton(Pipeline::class, static fn (Application $app): Pipeline => new Pipeline($app->make(Graph::class), new Psr17Factory(), $app->make(Graph::class)->config()->pathPrefix));
    }

    public function boot(Router $router, AuthManager $auth, Repository $config): void
    {
        $this->publishes([__DIR__ . '/../config/polaris.php' => $this->app->configPath('polaris.php')], 'polaris-config');
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'polaris');
        $this->publishes([__DIR__ . '/../resources/views' => $this->app->resourcePath('views/vendor/polaris')], 'polaris-views');
        $this->registerRoutes($router, $config);
        $auth->extend('polaris', function (LaravelApplication $app): PolarisGuard {
            $guard = new PolarisGuard($app->make(Graph::class), $app->make(Request::class));
            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
        if ($this->app->runningInConsole()) {
            $this->commands([InstallCommand::class]);
            CliCommands::register($this->app);
        }
    }

    /**
     * One Laravel route per manifest endpoint, plugins' included (`route:list` shows them,
     * `route('polaris.auth.login')` resolves), all served by the pipeline. No catch-all: at `path_prefix: /` a catch-all would shadow
     * the application's own routes, and an unknown path is then the application's 404.
     */
    private function registerRoutes(Router $router, Repository $config): void
    {
        $prefix = rtrim((string) $config->get('polaris.path_prefix', '/'), '/');
        $middleware = (array) $config->get('polaris.middleware', []);
        $manifest = (new Loader(...PolarisFactory::manifestDirectories((array) $config->get('polaris', []), $this->app)))->load();
        foreach ($manifest->endpoints() as $spec) {
            $router->match([$spec->method], $prefix . $spec->path, PolarisController::class)
                ->middleware($middleware)
                ->name('polaris.' . str_replace('/', '.', substr($spec->file, 0, -5)));
        }
    }
}

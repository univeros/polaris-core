<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Bootstrap\HandleExceptions;
use Illuminate\Support\Facades\Facade;
use Orchestra\Testbench\Foundation\Application as Testbench;
use Polaris\Laravel\PolarisServiceProvider;
use ReflectionFunction;

use function array_replace;
use function explode;
use function putenv;
use function restore_error_handler;
use function restore_exception_handler;
use function set_error_handler;
use function set_exception_handler;

/**
 * A booted Laravel application (the testbench skeleton) with the Polaris provider, the array cache,
 * no log output, and the `polaris` configuration overridden with the test's values (objects allowed).
 * One application lives at a time: creating the next flushes the previous one, and {@see reset()}
 * undoes what booting changed in the process (PHP's handlers, the facade root, environment variables).
 */
final class LaravelApp
{
    private static ?Application $current = null;

    /** @var list<string> */
    private static array $env = [];

    /**
     * @param array<string, mixed> $polaris
     * @param list<string> $env `KEY=value` lines set before the configuration loads
     * @param (callable(Application): void)|null $resolving runs on the bare application, before it boots
     */
    public static function create(array $polaris = [], array $env = [], ?callable $resolving = null): Application
    {
        self::reset();
        // The overrides land in a `booting` callback: after the configuration loaded, before the provider
        // boots, so the route table sees the test's prefix and plugins as a real config file would give them.
        $app = Testbench::create(resolvingCallback: static function (Application $app) use ($polaris, $resolving): void {
            $app->booting(static function () use ($app, $polaris): void {
                $config = $app->make(Repository::class);
                $config->set('polaris', array_replace((array) $config->get('polaris', []), $polaris));
            });
            if ($resolving !== null) {
                $resolving($app);
            }
        }, options: [
            'load_environment_variables' => false,
            'extra' => ['providers' => [PolarisServiceProvider::class], 'env' => $env],
        ]);
        self::$current = $app;
        foreach ($env as $line) {
            self::$env[] = explode('=', $line, 2)[0];
        }
        // Booting installed Laravel's error and exception handlers on top of PHPUnit's; the HTTP kernel
        // catches its own exceptions, and a test must leave the handlers as it found them.
        self::popLaravelHandlers();
        HandleExceptions::forgetApp();

        $config = $app->make(Repository::class);
        $config->set('cache.default', 'array');
        $config->set('logging.default', 'null');

        return $app;
    }

    private static function popLaravelHandlers(): void
    {
        $error = set_error_handler(static fn (): bool => false);
        restore_error_handler();
        if (self::isLaravels($error)) {
            restore_error_handler();
        }
        $exception = set_exception_handler(static fn (): null => null);
        restore_exception_handler();
        if (self::isLaravels($exception)) {
            restore_exception_handler();
        }
    }

    private static function isLaravels(mixed $handler): bool
    {
        return $handler instanceof \Closure && (new ReflectionFunction($handler))->getClosureThis() instanceof HandleExceptions;
    }

    public static function reset(): void
    {
        self::$current?->flush();
        self::$current = null;
        foreach (self::$env as $key) {
            putenv($key);
            unset($_ENV[$key], $_SERVER[$key]);
        }
        self::$env = [];
        Facade::clearResolvedInstances();
    }
}

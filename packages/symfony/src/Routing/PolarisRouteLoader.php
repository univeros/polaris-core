<?php

declare(strict_types=1);

namespace Polaris\Symfony\Routing;

use Override;
use Polaris\Contract\Plugin;
use Polaris\Http\Manifest\Loader as ManifestLoader;
use Polaris\Symfony\Http\PolarisController;
use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

use function rtrim;
use function str_replace;
use function substr;

/**
 * The `polaris` route type (`polaris: { resource: ., type: polaris }` in routes.yaml): one named route
 * per manifest endpoint, plugins' included (`polaris.auth.login`, ...) under `polaris.path_prefix`, all to the controller.
 */
final class PolarisRouteLoader extends Loader
{
    /**
     * @param iterable<Plugin> $plugins the configured plugins; their manifest directories join core's
     */
    public function __construct(private readonly ?string $manifestDirectory, private readonly string $pathPrefix, private readonly iterable $plugins = [])
    {
        parent::__construct();
    }

    #[Override]
    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        $routes = new RouteCollection();
        $prefix = rtrim($this->pathPrefix, '/');
        $directories = [$this->manifestDirectory ?? ManifestLoader::defaultDirectory()];
        foreach ($this->plugins as $plugin) {
            $directory = $plugin::manifestDirectory();
            if ($directory !== null) {
                $directories[] = $directory;
            }
        }
        $manifest = (new ManifestLoader(...$directories))->load();
        foreach ($manifest->endpoints() as $spec) {
            $routes->add(
                'polaris.' . str_replace('/', '.', substr($spec->file, 0, -5)),
                new Route($prefix . $spec->path, ['_controller' => PolarisController::class], methods: [$spec->method]),
            );
        }

        return $routes;
    }

    #[Override]
    public function supports(mixed $resource, ?string $type = null): bool
    {
        return $type === 'polaris';
    }
}

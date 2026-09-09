<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Polaris\Http\Endpoint;
use Polaris\Http\Manifest\Loader;
use Polaris\Http\Manifest\Manifest;

use function array_unique;

/**
 * Binds one {@see AltairEndpointBridge} per endpoint class the manifest references.
 */
final class EndpointBindings
{
    public function apply(Container $container, ?Manifest $manifest = null): void
    {
        $manifest ??= (new Loader(Loader::defaultDirectory()))->load();
        $classes = [];
        foreach ($manifest->endpoints() as $spec) {
            $classes[] = $spec->class;
        }
        foreach (array_unique($classes) as $class) {
            $container->singleton(
                AltairEndpointBridge::id($class),
                static function () use ($container, $class): AltairEndpointBridge {
                    $endpoint = $container->get($class);
                    assert($endpoint instanceof Endpoint);

                    return new AltairEndpointBridge($endpoint);
                },
            );
        }
    }
}

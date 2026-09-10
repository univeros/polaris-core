<?php

declare(strict_types=1);

namespace Polaris\Symfony\Tests;

use Override;
use Polaris\Symfony\PolarisBundle;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function md5;
use function serialize;
use function sys_get_temp_dir;

/**
 * A Symfony application for the tests: FrameworkBundle, the PolarisBundle with the given `polaris`
 * configuration, SecurityBundle when a `security` configuration is given (with a `/protected` route
 * behind it), and synthetic public services the test sets after boot. One compiled container per
 * configuration, cached in the temporary directory.
 */
final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * @param array<string, mixed> $polaris
     * @param array<string, mixed> $security
     * @param list<string> $synthetic
     */
    public function __construct(private readonly array $polaris, private readonly array $security = [], private readonly array $synthetic = [])
    {
        parent::__construct('test', true);
    }

    #[Override]
    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        if ($this->security !== []) {
            yield new SecurityBundle();
        }
        yield new PolarisBundle();
    }

    #[Override]
    public function getProjectDir(): string
    {
        return sys_get_temp_dir() . '/polaris-symfony-tests';
    }

    #[Override]
    public function getCacheDir(): string
    {
        return $this->getProjectDir() . '/cache/' . md5(serialize([$this->polaris, $this->security, $this->synthetic]));
    }

    #[Override]
    public function getLogDir(): string
    {
        return $this->getProjectDir() . '/log';
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'polaris-tests',
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'php_errors' => ['log' => true],
            'cache' => ['app' => 'cache.adapter.array'],
            'router' => ['utf8' => true],
            // Debug mode adds X-Robots-Tag: noindex to every response; a production kernel does not.
            'disallow_search_engine_index' => false,
        ]);
        // The framework's default logger writes to stderr in debug mode; the tests do not need the noise.
        $container->services()->set('logger', NullLogger::class);
        if ($this->security !== []) {
            $container->extension('security', $this->security);
            $container->services()->set(ProtectedController::class)->args([service('security.helper')])->tag('controller.service_arguments')->public();
        }
        $container->extension('polaris', $this->polaris);
        foreach ($this->synthetic as $id) {
            $container->services()->set($id)->synthetic()->public();
        }
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import('.', 'polaris');
        if ($this->security !== []) {
            $routes->add('protected', '/protected')->controller(ProtectedController::class);
        }
    }
}

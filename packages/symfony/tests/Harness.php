<?php

declare(strict_types=1);

namespace Polaris\Symfony\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use Override;
use Polaris\Support\InMemoryCache;
use Polaris\Tests\Functional\Harness as HarnessContract;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

use function is_array;
use function json_encode;
use function sprintf;
use function str_starts_with;
use function strip_tags;
use function substr;

use const JSON_THROW_ON_ERROR;

/**
 * The functional suite through Symfony (docs/adapters/spec.md §3.7): a real kernel with the bundle,
 * the test's Config objects handed to the bundle as synthetic services, every request pushed through
 * the HTTP kernel as bytes, every response converted back. `POLARIS_HARNESS=Polaris\Symfony\Tests\Harness`.
 */
final class Harness implements HarnessContract
{
    private const array SERVICES = ['secrets', 'auth', 'database', 'cache', 'mailer', 'sms', 'dispatcher'];
    private static ?TestKernel $previous = null;

    private function __construct(private readonly TestKernel $kernel)
    {
    }

    #[Override]
    public static function create(Config $config): static
    {
        self::$previous?->shutdown();
        $ids = [];
        foreach (self::SERVICES as $service) {
            $ids[$service] = 'polaris.test.' . $service;
        }
        $pluginIds = [];
        foreach ($config->plugins as $index => $plugin) {
            $pluginIds[$index] = 'polaris.test.plugin.' . $index;
        }
        $kernel = new TestKernel([
            'path_prefix' => $config->pathPrefix,
            'manifest_directory' => $config->manifestDirectory,
            'secrets' => ['service' => $ids['secrets']],
            'auth' => ['service' => $ids['auth']],
            'database' => ['service' => $ids['database']],
            // Symfony resets its array cache adapter between the requests one process handles (kernel.reset);
            // a production cache persists, and so does the test's own PSR-16 cache.
            'cache' => $ids['cache'],
            'mailer' => $ids['mailer'],
            'sms' => $ids['sms'],
            'dispatcher' => $ids['dispatcher'],
            'plugins' => array_values($pluginIds),
        ], synthetic: [...array_values($ids), ...array_values($pluginIds)]);
        $kernel->boot();
        $container = $kernel->getContainer();
        foreach (self::SERVICES as $service) {
            $container->set($ids[$service], $config->{$service} ?? ($service === 'cache' ? new InMemoryCache() : null));
        }
        foreach ($pluginIds as $index => $id) {
            $container->set($id, $config->plugins[$index]);
        }
        self::$previous = $kernel;

        return new self($kernel);
    }

    #[Override]
    public function graph(): Graph
    {
        return $this->kernel->getContainer()->get(Graph::class);
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $symfony = (new HttpFoundationFactory())->createRequest(self::wire($request));
        $response = $this->kernel->handle($symfony);
        $this->kernel->terminate($symfony, $response);
        if ($response->getStatusCode() >= 500) {
            throw new RuntimeException(sprintf('Symfony answered %d: %s', $response->getStatusCode(), substr(strip_tags((string) $response->getContent()), 0, 2000)));
        }
        $psr = (new PsrHttpFactory())->createResponse($response);
        // HttpFoundation makes the SAPI's default Content-Type explicit on a body-less response that
        // Polaris sent without one (the rate limiter's 429); on the wire every host sends it.
        if ((string) $psr->getBody() === '' && str_starts_with($psr->getHeaderLine('Content-Type'), 'text/html')) {
            $psr = $psr->withoutHeader('Content-Type');
        }

        return $psr;
    }

    /**
     * HttpFoundation always computes a Cache-Control for a response that has none.
     */
    #[Override]
    public static function transportHeaders(): array
    {
        return ['cache-control'];
    }

    /**
     * The tests build requests with a parsed body and no bytes; a client sends bytes, and bytes are
     * what the bridge parses on the way into the pipeline.
     */
    private static function wire(ServerRequestInterface $request): ServerRequestInterface
    {
        $wired = $request->hasHeader('Host') ? $request : $request->withHeader('Host', 'localhost');
        $parsed = $request->getParsedBody();
        if (is_array($parsed) && $parsed !== [] && (string) $request->getBody() === '') {
            $wired = $wired
                ->withBody((new Psr17Factory())->createStream(json_encode($parsed, JSON_THROW_ON_ERROR)))
                ->withParsedBody(null);
            if (!$wired->hasHeader('Content-Type')) {
                $wired = $wired->withHeader('Content-Type', 'application/json');
            }
        }

        return $wired;
    }
}

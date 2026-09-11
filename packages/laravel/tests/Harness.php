<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Http\Response as IlluminateResponse;
use Nyholm\Psr7\Factory\Psr17Factory;
use Override;
use Polaris\Tests\Functional\Harness as HarnessContract;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

use function is_array;
use function json_encode;
use function str_starts_with;

use const JSON_THROW_ON_ERROR;

/**
 * The functional suite through Laravel (docs/adapters/spec.md §3.7): a real application with the
 * provider, the test's Config handed to config/polaris.php, every request pushed through the HTTP
 * kernel as bytes, every response converted back. `POLARIS_HARNESS=Polaris\Laravel\Tests\Harness`.
 */
final class Harness implements HarnessContract
{
    private function __construct(private readonly Application $app)
    {
    }

    #[Override]
    public static function create(Config $config): static
    {
        return new self(LaravelApp::create([
            'path_prefix' => $config->pathPrefix,
            'secrets' => $config->secrets,
            'auth' => $config->auth,
            'rate_limits' => $config->rateLimits,
            'database' => $config->database,
            'mailer' => $config->mailer,
            'sms' => $config->sms,
            'dispatcher' => $config->dispatcher,
            'cache' => 'array',
            'manifest_directory' => $config->manifestDirectory,
            'plugins' => $config->plugins,
        ]));
    }

    #[Override]
    public function graph(): Graph
    {
        return $this->app->make(Graph::class);
    }

    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $illuminate = Request::createFromBase((new HttpFoundationFactory())->createRequest(self::wire($request)));
        $kernel = $this->app->make(Kernel::class);
        $response = $kernel->handle($illuminate);
        $kernel->terminate($illuminate, $response);
        if ($response->getStatusCode() >= 500 && $response instanceof IlluminateResponse && $response->exception !== null) {
            throw $response->exception;
        }
        $psr = (new PsrHttpFactory())->createResponse($response);
        // HttpFoundation makes the SAPI's default Content-Type explicit on a body-less response that
        // Polaris sent without one (the rate limiter's 429); on the wire every host sends it, so the
        // comparison sees Polaris's response.
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
     * what Laravel parses.
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

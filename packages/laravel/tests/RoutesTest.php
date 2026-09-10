<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use Polaris\Laravel\Http\PolarisController;
use Polaris\Laravel\PolarisServiceProvider;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\TestKeys;

use function array_filter;
use function array_keys;
use function json_decode;
use function str_repeat;
use function str_starts_with;

#[CoversClass(PolarisServiceProvider::class)]
#[CoversClass(PolarisController::class)]
final class RoutesTest extends LaravelTestCase
{
    public function testEveryManifestEndpointIsANamedLaravelRouteUnderThePrefix(): void
    {
        $app = LaravelApp::create(env: ['POLARIS_PATH_PREFIX=/api/auth']);
        $routes = $app->make(Router::class)->getRoutes();

        $login = $routes->getByName('polaris.auth.login');
        self::assertNotNull($login);
        self::assertSame('api/auth/auth/login', $login->uri());
        self::assertSame(['POST'], $login->methods());
        self::assertSame(PolarisController::class, $login->getActionName());
        self::assertSame('api/auth/orgs/{id}/members/{userId}', $routes->getByName('polaris.orgs.member-remove')?->uri());
        self::assertCount(52, array_filter(array_keys($routes->getRoutesByName()), static fn (string $name): bool => str_starts_with($name, 'polaris.')));
    }

    public function testTheKernelServesAManifestRouteThroughThePipeline(): void
    {
        $keys = TestKeys::rsa();
        $app = LaravelApp::create([
            'secrets' => ['app_key' => str_repeat('k', 32), 'jwt_private_key' => $keys['private'], 'jwt_public_key' => $keys['public'], 'jwt_kid' => 'kid-1'],
            'auth' => ['issuer' => 'https://issuer.test'],
            'database' => new InMemoryAdapter(),
        ]);

        $response = $app->make(Kernel::class)->handle(Request::create('/auth/.well-known/jwks.json'));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->headers->get('Content-Type'));
        self::assertSame('kid-1', json_decode((string) $response->getContent(), true)['keys'][0]['kid'] ?? null);
        // What HttpFoundation adds to every response, and what the contract harness ignores.
        self::assertSame('no-cache, private', $response->headers->get('Cache-Control'));

        $missing = $app->make(Kernel::class)->handle(Request::create('/auth/login', 'GET'));
        self::assertSame(405, $missing->getStatusCode());
    }
}

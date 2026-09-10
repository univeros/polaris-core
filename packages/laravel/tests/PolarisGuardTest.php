<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use DateTimeImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Laravel\Auth\PolarisGuard;
use Polaris\Laravel\Auth\PolarisUser;
use Polaris\Model\User;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function str_repeat;

#[CoversClass(PolarisGuard::class)]
#[CoversClass(PolarisUser::class)]
final class PolarisGuardTest extends LaravelTestCase
{
    private Application $app;
    private string $userId;
    private string $accessToken;

    protected function setUp(): void
    {
        parent::setUp();
        $keys = TestKeys::rsa();
        $this->app = LaravelApp::create([
            'secrets' => Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public']]),
            'auth' => AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            'database' => new InMemoryAdapter(),
        ]);
        $this->app->make(Repository::class)->set('auth.guards.polaris', ['driver' => 'polaris']);
        $graph = $this->app->make(Graph::class);

        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = 'ada@example.com';
        $user->emailVerifiedAt = new DateTimeImmutable();
        $user->createdAt = new DateTimeImmutable();
        $user->updatedAt = new DateTimeImmutable();
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();
        $this->userId = $user->id;
        $this->accessToken = $graph->tokens()->issue(new SessionPrincipal($user->id, emailVerified: true), ClientContext::none())->accessToken;
    }

    public function testAValidBearerIdentifiesThePolarisUser(): void
    {
        $guard = $this->guard('Bearer ' . $this->accessToken);

        $user = $guard->user();
        self::assertInstanceOf(PolarisUser::class, $user);
        self::assertSame($this->userId, $user->user->id);
        self::assertSame($this->userId, $user->claim('sub'));
        self::assertSame($this->userId, $guard->id());
        self::assertTrue($guard->check());
        self::assertSame($user, $guard->user());
    }

    public function testAnInvalidBearerIsAGuest(): void
    {
        $guard = $this->guard('Bearer not-a-token');

        self::assertNull($guard->user());
        self::assertTrue($guard->guest());
    }

    public function testNoBearerIsAGuest(): void
    {
        $guard = $this->guard(null);

        self::assertNull($guard->user());
        self::assertFalse($guard->validate(['email' => 'ada@example.com', 'password' => 'x']));
    }

    private function guard(?string $authorization): PolarisGuard
    {
        $this->app->instance('request', Request::create('/me', 'GET', server: $authorization === null ? [] : ['HTTP_AUTHORIZATION' => $authorization]));
        $guard = $this->app->make(AuthManager::class)->guard('polaris');
        self::assertInstanceOf(PolarisGuard::class, $guard);

        return $guard;
    }
}

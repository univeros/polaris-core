<?php

declare(strict_types=1);

namespace Polaris\Symfony\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Symfony\Security\PolarisAuthenticator;
use Polaris\Symfony\Security\PolarisUser;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Wiring\Graph;
use Symfony\Component\HttpFoundation\Request;

use function json_decode;

#[CoversClass(PolarisAuthenticator::class)]
#[CoversClass(PolarisUser::class)]
final class AuthenticatorTest extends TestCase
{
    private TestKernel $kernel;
    private string $userId;
    private string $accessToken;

    protected function setUp(): void
    {
        $this->kernel = new TestKernel(
            [
                'secrets' => ['service' => 'polaris.test.secrets'],
                'auth' => ['service' => 'polaris.test.auth'],
                'database' => ['service' => 'polaris.test.database'],
            ],
            [
                'firewalls' => ['api' => ['pattern' => '^/protected', 'stateless' => true, 'custom_authenticators' => [PolarisAuthenticator::class]]],
                'access_control' => [['path' => '^/protected', 'roles' => 'ROLE_USER']],
            ],
            ['polaris.test.secrets', 'polaris.test.auth', 'polaris.test.database'],
        );
        $this->kernel->boot();
        $container = $this->kernel->getContainer();
        $container->set('polaris.test.secrets', Fixtures::secrets());
        $container->set('polaris.test.auth', Fixtures::auth());
        $container->set('polaris.test.database', new InMemoryAdapter());
        $graph = $container->get(Graph::class);
        self::assertInstanceOf(Graph::class, $graph);
        ['id' => $this->userId, 'token' => $this->accessToken] = Fixtures::userWithToken($graph);
    }

    protected function tearDown(): void
    {
        $this->kernel->shutdown();
    }

    public function testAValidBearerAuthenticatesThePolarisUser(): void
    {
        $response = $this->kernel->handle(Request::create('/protected', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $this->accessToken]));

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame($this->userId, $body['id']);
        self::assertSame(['ROLE_USER', 'ROLE_POLARIS_OWNER'], $body['roles']);
    }

    public function testAnInvalidBearerIsUnauthorized(): void
    {
        $response = $this->kernel->handle(Request::create('/protected', server: ['HTTP_AUTHORIZATION' => 'Bearer not-a-token']));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer', $response->headers->get('WWW-Authenticate'));
        self::assertSame('unauthorized', json_decode((string) $response->getContent(), true)['error']);
    }

    public function testNoBearerIsUnauthorized(): void
    {
        $response = $this->kernel->handle(Request::create('/protected'));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer', $response->headers->get('WWW-Authenticate'));
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Tests\Wiring;

use DateTimeImmutable;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Authorization\Gate;
use Polaris\Authorization\PermissionCatalogSeeder;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\UserRegistered;
use Polaris\Psr15\Middleware\TokenAuthenticationMiddleware;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Functional\PipelineHarness;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\Plugin\StampResolverPlugin;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function array_key_last;
use function json_decode;
use function json_encode;
use function str_repeat;

/**
 * The bearer-resolver seam (program 4, decision #2) and the delegated authority (decision #3) through the
 * pipeline: a plugin authenticates its own credential on core's bearer routes, its refusal is core's
 * 401, a request it does not recognise reaches core's JWT parser, and the authority of a delegated
 * token is the intersection. Separate processes: the schema registry is static.
 */
#[CoversClass(Graph::class)]
#[CoversClass(Gate::class)]
#[CoversClass(TokenAuthenticationMiddleware::class)]
#[RunTestsInSeparateProcesses]
final class BearerResolverTest extends TestCase
{
    private const string NOW = '2026-10-10T10:00:00+00:00';
    private const string PASSWORD = 'correct horse battery staple';

    private PipelineHarness $harness;
    private RecordingEventDispatcher $events;

    public function testAPluginsCredentialAuthenticatesCoreRoutesWithTheDelegatedAuthority(): void
    {
        $plugin = new StampResolverPlugin(['org.read']);
        $this->boot($plugin);
        [$userId, $access] = $this->user('ada@example.com');
        $orgId = (string) $this->json($this->request('POST', '/orgs', ['name' => 'Acme'], $access))['data']['id'];

        self::assertSame([$plugin], $this->harness->graph()->bearerResolvers(), 'the graph collects the provider\'s resolvers');
        $me = $this->request('GET', '/auth/me', null, 'stamp:' . $userId);
        self::assertSame(200, $me->getStatusCode(), (string) $me->getBody());
        self::assertSame($userId, $this->json($me)['data']['id'], 'the key\'s owner');

        $read = $this->request('GET', '/orgs/' . $orgId, null, 'stamp:' . $userId . ':' . $orgId);
        self::assertSame(200, $read->getStatusCode(), 'org.read was delegated and is held: ' . $read->getBody());
        self::assertSame(403, $this->request('GET', '/orgs/' . $orgId . '/members', null, 'stamp:' . $userId . ':' . $orgId)->getStatusCode(), 'members.read is held but was not delegated');
        $switched = (string) $this->json($this->request('POST', '/auth/switch-org', ['organization_id' => $orgId], $access))['data']['access_token'];
        self::assertSame(200, $this->request('GET', '/orgs/' . $orgId . '/members', null, $switched)->getStatusCode(), 'the owner\'s own session is untouched');
        self::assertGreaterThan(0, $plugin->asked);
    }

    public function testARefusedCredentialIsCoresUnauthorizedAndAnUnknownOneReachesCoresParser(): void
    {
        $plugin = new StampResolverPlugin(null);
        $this->boot($plugin);
        [, $access] = $this->user('ada@example.com');

        $refused = $this->request('GET', '/auth/me', null, 'stamp:revoked');
        self::assertSame(401, $refused->getStatusCode());
        self::assertSame('unauthorized', $this->json($refused)['error'], 'core\'s envelope, not the plugin\'s reason');
        self::assertSame(401, $this->request('GET', '/auth/me', null, 'not-a-jwt')->getStatusCode());
        self::assertSame(200, $this->request('GET', '/auth/me', null, $access)->getStatusCode(), 'a core session passes the resolver and parses');
        self::assertSame(200, $this->request('GET', '/auth/.well-known/jwks.json', null, 'stamp:revoked')->getStatusCode(), 'public routes never ask');
    }

    private function boot(StampResolverPlugin $plugin): void
    {
        $keys = TestKeys::rsa();
        $this->events = new RecordingEventDispatcher();
        $this->harness = PipelineHarness::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: $adapter = new InMemoryAdapter(),
            clock: new FrozenClock(new DateTimeImmutable(self::NOW)),
            dispatcher: $this->events,
            plugins: [$plugin],
        ));
        (new PermissionCatalogSeeder($this->harness->graph()->permissionCatalog()))->seed($adapter, new DateTimeImmutable(self::NOW));
    }

    /**
     * @return array{string, string} the user id and an access token
     */
    private function user(string $email): array
    {
        $response = $this->request('POST', '/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        self::assertSame(202, $response->getStatusCode(), (string) $response->getBody());
        $events = $this->events->ofType(UserRegistered::class);
        $registered = $events[array_key_last($events)];
        $this->request('POST', '/auth/email/verify', ['token' => $registered->verificationToken]);
        $this->harness->graph()->unitOfWork()->clear();
        $login = $this->json($this->request('POST', '/auth/login', ['email' => $email, 'password' => self::PASSWORD]));

        return [$registered->userId, (string) $login['data']['access_token']];
    }

    /**
     * @param array<string, mixed>|null $body
     */
    private function request(string $method, string $path, ?array $body, ?string $bearer = null): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, 'https://issuer.test' . $path, ['REMOTE_ADDR' => '203.0.113.7']);
        if ($body !== null) {
            $request->getBody()->write((string) json_encode($body));
            $request = $request->withHeader('Content-Type', 'application/json')->withParsedBody($body);
        }
        if ($bearer !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $bearer);
        }

        return $this->harness->handle($this->withIp($request));
    }

    private function withIp(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request->withAttribute('polaris.ip_address', '203.0.113.7');
    }

    /**
     * @return array<string, mixed>
     */
    private function json(ResponseInterface $response): array
    {
        return (array) json_decode((string) $response->getBody(), true);
    }
}

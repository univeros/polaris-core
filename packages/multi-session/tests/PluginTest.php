<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Tests;

use DateTimeImmutable;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Model\User;
use Polaris\MultiSession\Devices;
use Polaris\MultiSession\Http\DeviceMiddleware;
use Polaris\MultiSession\MultiSessionException;
use Polaris\MultiSession\MultiSessionPlugin;
use Polaris\MultiSession\Schema;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Wiring\Graph;
use Polaris\Wiring\Config;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\Uid\Uuid;

use function array_column;
use function in_array;
use function json_decode;
use function str_repeat;

/**
 * The plugin wired through `Polaris::create()` and its middleware through the PSR-15 pipeline: the device
 * minted on a sign-in and only a known one accepted back (header or cookie), two accounts on one device,
 * switching without signing in again, revoking one, the last method. Separate processes: the schema
 * registry is static.
 */
#[CoversClass(MultiSessionPlugin::class)]
#[CoversClass(Devices::class)]
#[CoversClass(DeviceMiddleware::class)]
#[CoversClass(MultiSessionException::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-09T10:00:00+00:00';
    private const string PASSWORD = 'correct horse battery staple';

    private Graph $graph;
    private Pipeline $pipeline;

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = $this->boot();

        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[] = $model->table;
        }
        self::assertContains(Schema::DEVICES, $tables);
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (in_array('multi-session', $spec->tags, true)) {
                $this->graph->endpoint($spec->class);
                $routes[] = $spec->method . ' ' . $spec->path . ' ' . $spec->auth;
            }
        }
        self::assertEqualsCanonicalizing(['GET /multi-session/list bearer', 'POST /multi-session/switch bearer', 'DELETE /multi-session/{sessionId} bearer', 'GET /multi-session/last-method public'], $routes);
        self::assertSame(MultiSessionPlugin::ID, MultiSessionPlugin::of($this->graph)->id());
        self::assertInstanceOf(DeviceMiddleware::class, MultiSessionPlugin::of($this->graph)->middleware($this->graph)[0]);
    }

    public function testTwoAccountsOnOneDeviceSwitchWithoutSigningInAndRevokeOneAtATime(): void
    {
        $this->boot();
        $ada = $this->user('ada@example.com');
        $this->user('grace@example.com');

        self::assertNull($this->json($this->send('GET', '/multi-session/last-method'))['data']['last_method']);
        $first = $this->send('POST', '/auth/login', ['email' => 'ada@example.com', 'password' => self::PASSWORD]);
        $device = $first->getHeaderLine(DeviceMiddleware::HEADER);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $device, 'minted by the server');
        self::assertStringContainsString('polaris_ms_device=' . $device . '; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax', $first->getHeaderLine('Set-Cookie'));
        $adaSession = $this->json($first)['data'];
        self::assertSame('pwd', $this->json($this->send('GET', '/multi-session/last-method', device: $device))['data']['last_method']);

        $forged = $this->send('POST', '/auth/login', ['email' => 'grace@example.com', 'password' => self::PASSWORD], device: str_repeat('a', 64));
        self::assertNotSame(str_repeat('a', 64), $forged->getHeaderLine(DeviceMiddleware::HEADER), 'an id the server did not mint is not accepted');
        $second = $this->send('POST', '/auth/login', ['email' => 'grace@example.com', 'password' => self::PASSWORD], device: $device);
        $joined = $second->getHeaderLine(DeviceMiddleware::HEADER);
        self::assertNotSame($device, $joined, 'a sign-in that joins a device gets it a new id');
        $graceSession = $this->json($second)['data'];
        self::assertSame(403, $this->send('GET', '/multi-session/list', token: (string) $graceSession['access_token'], device: $device)->getStatusCode(), 'the old id names nothing');
        $device = $joined;
        self::assertSame($device, $this->send('POST', '/auth/token/refresh', ['refresh_token' => (string) $graceSession['refresh_token']], device: $device)->getHeaderLine(DeviceMiddleware::HEADER), 'a refresh keeps the id');

        $list = $this->json($this->send('GET', '/multi-session/list', token: (string) $graceSession['access_token'], device: $device))['data'];
        self::assertSame(['grace@example.com', 'ada@example.com'], array_column(array_column($list, 'user'), 'email'), 'the most recent sign-in first');
        self::assertSame([true, false], array_column($list, 'current'));
        self::assertSame(403, $this->send('GET', '/multi-session/list', token: (string) $graceSession['access_token'])->getStatusCode(), 'no device');
        self::assertSame(403, $this->send('GET', '/multi-session/list', token: (string) $this->json($forged)['data']['access_token'], device: $device)->getStatusCode(), 'a session of another device');
        self::assertSame(200, $this->send('GET', '/multi-session/list', token: (string) $graceSession['access_token'], cookie: $device)->getStatusCode(), 'the cookie works as the header');

        $adaSid = $this->claims((string) $adaSession['access_token'])['sid'];
        self::assertSame(404, $this->send('POST', '/multi-session/switch', ['session_id' => 'nope'], (string) $graceSession['access_token'], $device)->getStatusCode());
        self::assertSame(422, $this->send('POST', '/multi-session/switch', [], (string) $graceSession['access_token'], $device)->getStatusCode());
        $switched = $this->send('POST', '/multi-session/switch', ['session_id' => $adaSid], (string) $graceSession['access_token'], $device);
        $envelope = $this->json($switched)['data'];
        self::assertSame([200, $ada->id], [$switched->getStatusCode(), $envelope['user']['id']], 'a fresh envelope for ada without her password');
        $claims = $this->claims((string) $envelope['access_token']);
        self::assertSame(['pwd'], $claims['amr'], 'the stored authentication facts');
        self::assertNotSame($adaSid, $claims['sid']);
        self::assertSame(401, $this->send('POST', '/auth/token/refresh', ['refresh_token' => (string) $adaSession['refresh_token']])->getStatusCode(), 'the old session ended');
        self::assertSame(200, $this->send('GET', '/auth/me', token: (string) $graceSession['access_token'])->getStatusCode(), 'the caller\'s own session stays');
        self::assertNotNull($this->graph->database()->findOne('auth_refresh_tokens', ['family_id' => $this->claims((string) $graceSession['access_token'])['sid'], 'revoked_at' => null]));
        self::assertSame('pwd', $this->json($this->send('GET', '/multi-session/last-method', device: $device))['data']['last_method'], 'a switch is not a sign-in');

        self::assertSame(200, $this->send('DELETE', '/multi-session/' . $claims['sid'], token: (string) $graceSession['access_token'], device: $device)->getStatusCode());
        self::assertSame(401, $this->send('POST', '/auth/token/refresh', ['refresh_token' => (string) $envelope['refresh_token']])->getStatusCode(), 'ada is signed out');
        $list = $this->json($this->send('GET', '/multi-session/list', token: (string) $graceSession['access_token'], device: $device))['data'];
        self::assertSame(['grace@example.com'], array_column(array_column($list, 'user'), 'email'), 'grace stays');
        self::assertSame(404, $this->send('DELETE', '/multi-session/' . $claims['sid'], token: (string) $graceSession['access_token'], device: $device)->getStatusCode(), 'once');
    }

    public function testASwitchKeepsMfaAuthTimeAndTheOrganizationOfTheSession(): void
    {
        $this->boot();
        $ada = $this->user('ada@example.com');
        $grace = $this->user('grace@example.com');
        $organization = $this->graph->organizations()->create('Acme', null, $ada->id)->id;
        $devices = $this->graph->get(Devices::class);
        $client = new ClientContext(null, null);
        $adaTokens = $this->graph->tokens()->issue(new SessionPrincipal($ada->id, $organization, [], [], true, true, ['pwd', 'otp'], 1760000000), $client);
        $graceTokens = $this->graph->tokens()->issue(new SessionPrincipal($grace->id, amr: ['magic_link']), $client);
        $device = $devices->record(Devices::mint(), $ada->id, $adaTokens->sessionId, ['pwd', 'otp']);
        $device = $devices->record($device, $grace->id, $graceTokens->sessionId, ['magic_link']);
        self::assertTrue($devices->known($device));
        self::assertSame('magic_link', $devices->lastMethod($device));

        $claims = $this->claims((string) $devices->switch($device, $graceTokens->sessionId, $adaTokens->sessionId, $client)['access_token']);
        self::assertSame([['pwd', 'otp'], true, 1760000000, $organization], [$claims['amr'], $claims['mfa'], $claims['auth_time'], $claims['org']]);

        $ada->status = User::STATUS_DISABLED;
        $this->graph->unitOfWork()->persist($ada);
        $this->graph->unitOfWork()->flush();
        try {
            $devices->switch($device, $graceTokens->sessionId, $claims['sid'], $client);
            self::fail('a disabled account is not switched to');
        } catch (MultiSessionException $exception) {
            self::assertSame(MultiSessionException::SESSION_NOT_FOUND, $exception->reason);
        }
    }

    public function testAPlantedDeviceIdDoesNotLetItsOwnerIntoTheNextSignIn(): void
    {
        $this->boot();
        $this->user('mallory@example.com');
        $this->user('ada@example.com');

        $mallory = $this->send('POST', '/auth/login', ['email' => 'mallory@example.com', 'password' => self::PASSWORD]);
        $planted = $mallory->getHeaderLine(DeviceMiddleware::HEADER);
        $ada = $this->send('POST', '/auth/login', ['email' => 'ada@example.com', 'password' => self::PASSWORD], cookie: $planted);
        $device = $ada->getHeaderLine(DeviceMiddleware::HEADER);
        self::assertNotSame($planted, $device);
        self::assertStringContainsString('polaris_ms_device=' . $device, $ada->getHeaderLine('Set-Cookie'), 'the browser gets the new id');
        self::assertSame(403, $this->send('GET', '/multi-session/list', token: (string) $this->json($mallory)['data']['access_token'], device: $planted)->getStatusCode(), 'the planted id names nothing any more');
        $list = $this->json($this->send('GET', '/multi-session/list', token: (string) $this->json($ada)['data']['access_token'], device: $device))['data'];
        self::assertSame(['ada@example.com', 'mallory@example.com'], array_column(array_column($list, 'user'), 'email'), 'only the browser holding the new id sees both');
    }

    public function testWithoutTheCookieOnlyTheHeaderCarriesTheDevice(): void
    {
        $this->boot(new MultiSessionPlugin(cookie: false));
        $this->user('ada@example.com');

        $response = $this->send('POST', '/auth/login', ['email' => 'ada@example.com', 'password' => self::PASSWORD]);
        self::assertNotSame('', $response->getHeaderLine(DeviceMiddleware::HEADER));
        self::assertSame('', $response->getHeaderLine('Set-Cookie'));
        self::assertSame('', $this->send('POST', '/auth/login', ['email' => 'ada@example.com', 'password' => 'wrong'])->getHeaderLine(DeviceMiddleware::HEADER), 'no token pair, no device');
    }

    /**
     * @param array<string, mixed>|null $body
     */
    private function send(string $method, string $path, ?array $body = null, ?string $token = null, ?string $device = null, ?string $cookie = null): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, 'https://app.example' . $path, ['REMOTE_ADDR' => '203.0.113.7']);
        if ($body !== null) {
            $request = $request->withHeader('Content-Type', 'application/json')->withParsedBody($body);
        }
        if ($token !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token);
        }
        if ($device !== null) {
            $request = $request->withHeader(DeviceMiddleware::HEADER, $device);
        }
        if ($cookie !== null) {
            $request = $request->withCookieParams([DeviceMiddleware::COOKIE => $cookie]);
        }

        return $this->pipeline->handle($request);
    }

    /**
     * @return array<string, mixed>
     */
    private function json(ResponseInterface $response): array
    {
        $decoded = json_decode((string) $response->getBody(), true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(string $accessToken): array
    {
        return $this->graph->tokenFactory()->fromTokenString($accessToken)->getMetadata();
    }

    private function user(string $email): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->passwordHash = $this->graph->passwordHasher()->hash(self::PASSWORD);
        $user->emailVerifiedAt = new DateTimeImmutable(self::NOW);
        $user->createdAt = $user->updatedAt = new DateTimeImmutable(self::NOW);
        $this->graph->unitOfWork()->persist($user);
        $this->graph->unitOfWork()->flush();

        return $user;
    }

    private function boot(MultiSessionPlugin $plugin = new MultiSessionPlugin()): Polaris
    {
        $keys = TestKeys::rsa();
        $polaris = Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: new FrozenClock(new DateTimeImmutable(self::NOW)),
            plugins: [$plugin],
        ));
        $this->graph = $polaris->graph();
        $this->pipeline = new Pipeline($this->graph, new ResponseFactory());

        return $polaris;
    }
}

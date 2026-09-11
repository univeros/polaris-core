<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Tests;

use DateTimeImmutable;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Cli\Application;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\UserLoggedIn;
use Polaris\Event\UserLoginFailed;
use Polaris\Http\Attributes;
use Polaris\Messaging\Channel\ArrayChannel;
use Polaris\Messaging\Message;
use Polaris\Messaging\MessagePolicy;
use Polaris\Messaging\MessagingPlugin;
use Polaris\Messaging\Suppressor;
use Polaris\Messaging\Tests\Support\FakeHttpClient;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Schema\Schema as CoreSchema;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\AuditNames;
use Polaris\Sentinel\Console\ListsCommand;
use Polaris\Sentinel\Decision;
use Polaris\Sentinel\Decisions;
use Polaris\Sentinel\Devices;
use Polaris\Sentinel\Engine;
use Polaris\Sentinel\Http\SentinelMiddleware;
use Polaris\Sentinel\IpRules;
use Polaris\Sentinel\Listener;
use Polaris\Sentinel\Model\IpRule;
use Polaris\Sentinel\Provider\BotVerifier;
use Polaris\Sentinel\Provider\GeoPoint;
use Polaris\Sentinel\Provider\GeoResolver;
use Polaris\Sentinel\QuietMode;
use Polaris\Sentinel\Schema;
use Polaris\Sentinel\SentinelEvaluated;
use Polaris\Sentinel\SentinelPlugin;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Signal\CredentialStuffing;
use Polaris\Sentinel\Signal\DeviceSignal;
use Polaris\Sentinel\Signal\ImpossibleTravel;
use Polaris\Sentinel\Signal\IpList;
use Polaris\Sentinel\Verdict;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;
use Symfony\Component\Console\Tester\CommandTester;

use function file_get_contents;
use function in_array;
use function json_decode;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * The plugin wired through `Polaris::create()`: its tables, routes, services, middleware, listener and
 * command; the engine judging attempts through the middleware in memory. Separate processes: the
 * schema registry is static.
 */
#[CoversClass(SentinelPlugin::class)]
#[CoversClass(SentinelMiddleware::class)]
#[CoversClass(Engine::class)]
#[CoversClass(Listener::class)]
#[CoversClass(Decisions::class)]
#[CoversClass(Devices::class)]
#[CoversClass(IpRules::class)]
#[CoversClass(IpList::class)]
#[CoversClass(DeviceSignal::class)]
#[CoversClass(ImpossibleTravel::class)]
#[CoversClass(QuietMode::class)]
#[CoversClass(SentinelEvaluated::class)]
#[CoversClass(ListsCommand::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-09-11T10:00:00+00:00';
    private const string IP = '203.0.113.7';

    public function testEverythingIsWiredThroughTheGraphAndMessagingTakesTheQuietMode(): void
    {
        $polaris = self::polaris(new SentinelPlugin());
        $graph = $polaris->graph();

        self::assertCount(24, $polaris->schema(), 'core, audit, admin, messaging and the three sentinel tables');
        self::assertSame(Schema::DECISIONS, CoreSchema::for(\Polaris\Sentinel\Model\DecisionRecord::class)->table);
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (in_array('sentinel', $spec->tags, true)) {
                self::assertSame('public', $spec->auth, $spec->file . ' leaves the bearer to the admin middleware');
                self::assertContains('admin', $spec->tags, $spec->file . ' is resolved by the admin middleware');
                self::assertStringStartsWith('/admin/sentinel', $spec->path, $spec->file);
                $graph->endpoint($spec->class);
                $routes[] = $spec->method . ' ' . $spec->path;
            }
        }
        sort($routes);
        self::assertSame(['DELETE /admin/sentinel/ip-rules/{id}', 'GET /admin/sentinel/decisions', 'GET /admin/sentinel/ip-rules', 'POST /admin/sentinel/ip-rules', 'POST /admin/sentinel/unblock'], $routes);
        self::assertInstanceOf(SentinelMiddleware::class, $polaris->plugin(SentinelPlugin::ID)->middleware($graph)[0]);
        $catalog = $graph->get(Catalog::class);
        foreach (AuditNames::ALL as $name => $description) {
            self::assertTrue($catalog->has($name), $name);
        }
        self::assertCount(6, $polaris->listeners(), 'core\'s three, audit\'s two and the sentinel\'s');
        self::assertSame(SentinelPlugin::OBSERVE, SentinelPlugin::of($graph)->mode());
        self::assertInstanceOf(QuietMode::class, $graph->port(Suppressor::class));

        $graph->get(Engine::class)->evaluate(new Attempt(Attempt::SIGN_UP, 'ada@mailinator.com', self::IP));
        $policy = $graph->get(MessagePolicy::class);
        self::assertFalse($policy->allows(new Message(Message::EMAIL, 'ada@mailinator.com', 'email.new_device', 'text')), 'a challenged recipient gets no non-essential mail');
        self::assertTrue($policy->allows(new Message(Message::EMAIL, 'ada@mailinator.com', 'email.verify', 'text', essential: true)));
        self::assertTrue($policy->allows(new Message(Message::SMS, '+15551234567', 'sms.otp', 'text')));
        self::assertTrue($policy->allows(new Message(Message::EMAIL, 'bob@example.com', 'email.new_device', 'text')));
    }

    public function testObserveModeRecordsWhatASignalSaidAndLetsEverythingThrough(): void
    {
        $events = new RecordingEventDispatcher();
        $polaris = self::polaris(new SentinelPlugin(responses: new ResponseFactory()), events: $events);
        $graph = $polaris->graph();
        $events->listen(...$polaris->listeners());
        $middleware = $polaris->plugin(SentinelPlugin::ID)->middleware($graph)[0];

        $clean = $middleware->process(self::request($polaris, '/auth/register', ['email' => 'ada@example.com', 'password' => 'x']), self::handler());
        self::assertSame(201, $clean->getStatusCode());
        self::assertMatchesRegularExpression('/^polaris_device=[0-9a-f]{32}; Path=\/; Max-Age=31536000; HttpOnly; SameSite=Lax$/', $clean->getHeaderLine('Set-Cookie'), 'a device cookie for a request without one');
        self::assertCount(0, $graph->get(Decisions::class)->list()['data'], 'silence is not recorded');

        $flagged = $middleware->process(self::request($polaris, '/auth/register', ['email' => 'ada@mailinator.com', 'password' => 'x'], cookie: 'dev-1'), self::handler());
        self::assertSame(201, $flagged->getStatusCode(), 'observe mode enforces nothing');
        self::assertFalse($flagged->hasHeader('Set-Cookie'), 'the request had a device cookie');
        $decision = $graph->get(Decisions::class)->list()['data'][0];
        self::assertSame(['sign_up', 'ada@mailinator.com', self::IP, 60, 'challenge', false, ['disposable_email'], ['disposable domain mailinator.com']], [$decision['kind'], $decision['email'], $decision['ip'], $decision['score'], $decision['action'], $decision['enforced'], $decision['signals'], $decision['reasons']]);
        $event = $graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::EVALUATED]))->events[0];
        self::assertSame(['system', self::IP, 'ua/1'], [$event->actorType, $event->ip, $event->userAgent]);
        self::assertSame(['kind' => 'sign_up', 'email_hash' => hash('sha256', 'ada@mailinator.com'), 'score' => 60, 'action' => 'challenge', 'enforced' => false, 'signals' => ['disposable_email'], 'reasons' => ['disposable domain mailinator.com']], $event->data, 'the email is hashed in the audit store');

        $other = $middleware->process(self::request($polaris, '/auth/me', []), self::handler());
        self::assertSame(201, $other->getStatusCode());
        self::assertFalse($other->hasHeader('Set-Cookie'), 'an unguarded route is untouched');
        self::assertCount(1, $graph->get(Decisions::class)->list()['data']);
    }

    public function testEnforceModeBlocksChallengesWhenACaptchaCanAnswerAndHonoursTheRules(): void
    {
        $verifier = new class implements BotVerifier {
            public function verify(string $token, ?string $ip): bool
            {
                return $token === 'good';
            }
        };
        $polaris = self::polaris(new SentinelPlugin(mode: SentinelPlugin::ENFORCE, verifier: $verifier, responses: new ResponseFactory()));
        $graph = $polaris->graph();
        $middleware = $polaris->plugin(SentinelPlugin::ID)->middleware($graph)[0];
        $signUp = ['email' => 'ada@mailinator.com', 'password' => 'x'];

        $challenged = $middleware->process(self::request($polaris, '/auth/register', $signUp), self::handler());
        $this->assertProblem($challenged, 403, 'sentinel/challenge_required', 'sentinel_challenge_required');
        self::assertSame('captcha', json_decode((string) $challenged->getBody(), true)['challenge']);
        self::assertSame(201, $middleware->process(self::request($polaris, '/auth/register', [...$signUp, 'captcha_token' => 'good']), self::handler())->getStatusCode(), 'the retry with a valid token passes');
        $this->assertProblem($middleware->process(self::request($polaris, '/auth/register', [...$signUp, 'captcha_token' => 'bad']), self::handler()), 403, 'sentinel/blocked', 'sentinel_blocked');
        self::assertSame(['block', 'allow', 'challenge'], array_column($graph->get(Decisions::class)->list()['data'], 'action'), 'newest first, every one enforced');
        self::assertSame([true, true, true], array_column($graph->get(Decisions::class)->list()['data'], 'enforced'));

        $graph->get(IpRules::class)->add(self::IP, IpRule::ALLOW, 'office', 'test');
        self::assertSame(201, $middleware->process(self::request($polaris, '/auth/register', $signUp), self::handler())->getStatusCode(), 'an allow rule clears the address');
        self::assertSame(['ip_list', 'disposable_email'], $graph->get(Decisions::class)->list()['data'][0]['signals']);
        $graph->get(IpRules::class)->add('198.51.100.0/24', IpRule::BLOCK, 'scanner', 'test');
        $blocked = $middleware->process(self::request($polaris, '/auth/login', ['email' => 'ada@example.com', 'password' => 'x'], ip: '198.51.100.9'), self::handler());
        $this->assertProblem($blocked, 403, 'sentinel/blocked', 'sentinel_blocked');
        self::assertSame('The request was refused.', json_decode((string) $blocked->getBody(), true)['detail'], 'the reason stays in the record');
        self::assertSame(['address blocked by rule 198.51.100.0/24'], $graph->get(Decisions::class)->list(ip: '198.51.100.9')['data'][0]['reasons']);
    }

    public function testWithoutACaptchaVerifierTheChallengeBandIsRecordedAndLetThrough(): void
    {
        $polaris = self::polaris(new SentinelPlugin(mode: SentinelPlugin::ENFORCE, responses: new ResponseFactory()));
        $middleware = $polaris->plugin(SentinelPlugin::ID)->middleware($polaris->graph())[0];

        self::assertSame(201, $middleware->process(self::request($polaris, '/auth/register', ['email' => 'ada@mailinator.com', 'password' => 'x']), self::handler())->getStatusCode());
        $decision = $polaris->graph()->get(Decisions::class)->list()['data'][0];
        self::assertSame(['challenge', true], [$decision['action'], $decision['enforced']]);
    }

    public function testTheListenerRecordsDevicesAndFailuresForTheDeviceTravelAndStuffingSignals(): void
    {
        $geo = new class implements GeoResolver {
            public function resolve(string $ip): ?GeoPoint
            {
                return match ($ip) {
                    '203.0.113.7' => new GeoPoint(48.8566, 2.3522),
                    '198.51.100.9' => new GeoPoint(40.7128, -74.0060),
                    default => null,
                };
            }
        };
        $clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $events = new RecordingEventDispatcher();
        $polaris = self::polaris(new SentinelPlugin(geo: $geo, velocity: ['ip' => [100, 600], 'email' => [100, 600], 'device' => [100, 600]]), $clock, $events);
        $graph = $polaris->graph();
        $events->listen(...$polaris->listeners());
        $user = new User();
        $user->id = 'u1';
        $user->email = 'ada@example.com';
        $user->createdAt = $user->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();
        $engine = $graph->get(Engine::class);

        self::assertSame(Decision::ALLOW, $engine->evaluate(new Attempt(Attempt::SIGN_IN, 'ada@example.com', self::IP, deviceId: 'dev-1'))->action, 'no known device yet');
        $events->dispatch(new UserLoggedIn('u1', 'sid-1', self::IP));
        $device = $graph->get(Devices::class)->find('u1', 'dev-1');
        self::assertNotNull($device);
        self::assertSame([self::IP, '48.8566', '2.3522'], [$device->ip, $device->latitude, $device->longitude]);
        self::assertSame(1, $graph->get(Devices::class)->countFor('u1'));

        self::assertSame(0, $engine->evaluate(new Attempt(Attempt::SIGN_IN, 'ada@example.com', self::IP, deviceId: 'dev-1'))->score, 'the known device from the same place');
        $clock->advance('+1 hour');
        $travel = $engine->evaluate(new Attempt(Attempt::SIGN_IN, 'ada@example.com', '198.51.100.9', deviceId: 'dev-2'));
        self::assertSame([Decision::BLOCK, 100, ['device', 'impossible_travel']], [$travel->action, $travel->score, $travel->signals()]);
        self::assertSame('unknown device', $travel->reasons()[0]);
        self::assertStringContainsString('km/h', $travel->reasons()[1]);
        self::assertSame(['no device cookie'], $engine->evaluate(new Attempt(Attempt::SIGN_IN, 'ada@example.com', self::IP))->reasons());
        self::assertSame(0, $engine->evaluate(new Attempt(Attempt::SIGN_IN, 'bob@example.com', '198.51.100.9', deviceId: 'dev-9'))->score, 'an unknown user has no devices');
        $events->dispatch(new UserLoggedIn('u1', 'sid-2', '198.51.100.9'));
        self::assertSame(2, $graph->get(Devices::class)->countFor('u1'), 'the device of the attempt in flight');

        for ($i = 0; $i < 10; ++$i) {
            $engine->evaluate(new Attempt(Attempt::SIGN_IN, 'ada@example.com', '192.0.2.1', deviceId: 'dev-1'));
            $events->dispatch(new UserLoginFailed('u1', '192.0.2.1'));
        }
        $stuffed = $engine->evaluate(new Attempt(Attempt::SIGN_IN, 'ada@example.com', '192.0.2.1', deviceId: 'dev-1'));
        self::assertContains(CredentialStuffing::NAME, $stuffed->signals());
        self::assertSame('10 of 11 sign-ins from the address failed', $stuffed->reasons()[0]);
    }

    public function testTheEngineFailsOpenAndUnblockClearsTheCounters(): void
    {
        $broken = new class implements Signal {
            public function name(): string
            {
                return 'broken';
            }

            public function evaluate(Attempt $attempt): Verdict
            {
                throw new RuntimeException('provider down');
            }
        };
        $polaris = self::polaris(new SentinelPlugin(signals: [$broken], velocity: ['email' => [1, 600]]));
        $engine = $polaris->graph()->get(Engine::class);
        $attempt = new Attempt(Attempt::PASSWORD_RESET, 'ada@example.com', self::IP);

        self::assertSame(Decision::ALLOW, $engine->evaluate($attempt)->action, 'the broken signal is skipped');
        self::assertSame(50, $engine->evaluate($attempt)->score, 'the second attempt is over the email limit');
        $engine->unblock('ada@example.com');
        self::assertSame(0, $engine->evaluate($attempt)->score);
        self::assertFalse($engine->enforces());
        self::assertNull($engine->signal(ImpossibleTravel::class), 'no geo resolver, no travel signal');
    }

    public function testTheListsCommandFetchesADomainListIntoAFile(): void
    {
        $file = (string) tempnam(sys_get_temp_dir(), 'polaris-domains');
        try {
            $polaris = self::polaris(new SentinelPlugin(httpClient: new FakeHttpClient(200, "# source\nA.example\n\nb.example\n"), requestFactory: new RequestFactory()));
            $app = new Application($polaris);
            $app->setAutoExit(false);
            $lists = new CommandTester($app->find('sentinel:lists'));
            self::assertSame(2, $lists->execute([]), 'no URL, nothing fetched');
            self::assertSame(0, $lists->execute(['--url' => 'https://lists.example/disposable.txt', '--to' => $file]));
            self::assertStringContainsString('Wrote 2 domains', $lists->getDisplay());
            self::assertSame("# Disposable email domains, one per line. Source: https://lists.example/disposable.txt.\na.example\nb.example\n", file_get_contents($file));

            $offline = new Application(self::polaris(new SentinelPlugin()));
            $offline->setAutoExit(false);
            self::assertSame(1, (new CommandTester($offline->find('sentinel:lists')))->execute(['--url' => 'https://lists.example/x', '--to' => $file]), 'no HTTP client');
        } finally {
            unlink($file);
        }
    }

    private function assertProblem(ResponseInterface $response, int $status, string $type, string $error): void
    {
        self::assertSame($status, $response->getStatusCode());
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame(['https://polaris.univeros.io/problems/' . $type, $status, $error], [$body['type'], $body['status'], $body['error']]);
        self::assertSame($body['detail'], $body['message']);
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function request(Polaris $polaris, string $path, array $body, string $ip = self::IP, ?string $cookie = null): ServerRequestInterface
    {
        $spec = null;
        foreach ($polaris->manifest()->endpoints() as $candidate) {
            if ($candidate->path === $path && $candidate->method === ($body === [] ? 'GET' : 'POST')) {
                $spec = $candidate;
            }
        }
        self::assertNotNull($spec, $path);
        $request = (new ServerRequestFactory())->createServerRequest($body === [] ? 'GET' : 'POST', $path)
            ->withAttribute(Attributes::ROUTE, $spec)
            ->withAttribute(Attributes::IP_ADDRESS, $ip)
            ->withAttribute(Attributes::USER_AGENT, 'ua/1')
            ->withParsedBody($body);

        return $cookie === null ? $request : $request->withCookieParams([SentinelMiddleware::COOKIE => $cookie]);
    }

    private static function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response\JsonResponse(['data' => ['ok' => true]], 201);
            }
        };
    }

    private static function polaris(SentinelPlugin $sentinel, ?MutableClock $clock = null, ?RecordingEventDispatcher $events = null): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: $clock ?? new MutableClock(new DateTimeImmutable(self::NOW)),
            dispatcher: $events,
            plugins: [new AuditPlugin(), new AdminPlugin(), new MessagingPlugin(channels: [new ArrayChannel('mail', [Message::EMAIL]), new ArrayChannel('sms', [Message::SMS])]), $sentinel],
        ));
    }
}

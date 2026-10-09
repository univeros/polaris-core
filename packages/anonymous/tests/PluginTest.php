<?php

declare(strict_types=1);

namespace Polaris\Anonymous\Tests;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Anonymous\AnonymousException;
use Polaris\Anonymous\AnonymousPlugin;
use Polaris\Anonymous\Console\PruneCommand;
use Polaris\Anonymous\Guests;
use Polaris\Anonymous\Schema;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\UserDeleted;
use Polaris\Event\UserLoggedIn;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Uid\Uuid;

use function in_array;
use function str_repeat;

/**
 * The plugin wired through `Polaris::create()`, the guest session, the conversion through the host's
 * hook and its refusals, and the pruning of the guests nobody converted. Separate processes: the schema
 * registry is static.
 */
#[CoversClass(AnonymousPlugin::class)]
#[CoversClass(Guests::class)]
#[CoversClass(AnonymousException::class)]
#[CoversClass(PruneCommand::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-09T10:00:00+00:00';

    /** @var list<array{string, string}> */
    private array $converted = [];
    private MutableClock $clock;
    private RecordingEventDispatcher $events;
    private ClientContext $client;

    protected function setUp(): void
    {
        $this->clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $this->events = new RecordingEventDispatcher();
        $this->client = new ClientContext('203.0.113.7', 'ua/1');
    }

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();

        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[] = $model->table;
        }
        self::assertContains(Schema::GUESTS, $tables);
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (in_array('anonymous', $spec->tags, true)) {
                $graph->endpoint($spec->class);
                $routes[] = $spec->method . ' ' . $spec->path . ' ' . $spec->auth;
            }
        }
        self::assertEqualsCanonicalizing(['POST /anonymous/sign-in public', 'POST /anonymous/convert bearer'], $routes);
        $plugin = AnonymousPlugin::of($graph);
        self::assertSame('anonymous:prune', $plugin->commands($graph)[0]->getName());
        $this->expectException(LogicException::class);
        new AnonymousPlugin(pruneAfterDays: 0);
    }

    public function testAGuestIsAPasswordlessUserWithAPlaceholderEmailAndAnAnonymousSession(): void
    {
        $graph = $this->polaris()->graph();
        $data = $graph->get(Guests::class)->signIn($this->client);

        $claims = $graph->tokenFactory()->fromTokenString((string) $data['access_token'])->getMetadata();
        self::assertSame([['anonymous'], null], [$claims['amr'], $claims['org'] ?? null]);
        self::assertSame($data['user']['id'] . '@anonymous.invalid', $data['user']['email']);
        self::assertFalse($data['user']['email_verified']);
        $user = $graph->users()->find($data['user']['id']);
        self::assertInstanceOf(User::class, $user);
        self::assertSame([null, null, User::STATUS_ACTIVE], [$user->passwordHash, $user->emailVerifiedAt, $user->status]);
        self::assertTrue($graph->get(Guests::class)->isGuest($user->id));
        self::assertSame(['anonymous'], $this->events->ofType(UserLoggedIn::class)[0]->amr);
    }

    public function testConversionHandsBothIdsToTheHostThenEndsAndDisablesTheGuest(): void
    {
        $graph = $this->polaris()->graph();
        $guests = $graph->get(Guests::class);
        $guest = $guests->signIn($this->client);
        $other = $guests->signIn($this->client);
        $ada = $this->user($graph, 'ada@example.com');
        $session = $graph->tokens()->issue(new SessionPrincipal($ada->id, amr: ['magic_link']), $this->client);

        $this->refused(fn() => $guests->convert($ada->id, $session->accessToken), AnonymousException::NOT_A_GUEST, 'a real account is not a guest');
        $this->refused(fn() => $guests->convert($guest['user']['id'], 'not-a-token'), AnonymousException::TOKEN_INVALID);
        $this->refused(fn() => $guests->convert($guest['user']['id'], (string) $guest['access_token']), AnonymousException::TOKEN_INVALID, 'not into itself');
        $this->refused(fn() => $guests->convert($guest['user']['id'], (string) $other['access_token']), AnonymousException::TOKEN_INVALID, 'not into another guest');
        $impersonation = $graph->tokens()->mint(new SessionPrincipal($ada->id));
        $this->refused(fn() => $guests->convert($guest['user']['id'], $impersonation), AnonymousException::TOKEN_INVALID, 'only a live session');
        self::assertSame([], $this->converted, 'the hook ran for none of them');

        self::assertSame(['guest_id' => $guest['user']['id'], 'user_id' => $ada->id], $guests->convert($guest['user']['id'], $session->accessToken));
        self::assertSame([[$guest['user']['id'], $ada->id]], $this->converted);
        $row = $graph->database()->findOne(Schema::GUESTS, ['user_id' => $guest['user']['id']]);
        self::assertSame($ada->id, $row['converted_user_id'] ?? null);
        self::assertNotNull($row['converted_at'] ?? null);
        self::assertSame(User::STATUS_DISABLED, $graph->users()->find($guest['user']['id'])?->status, 'the guest\'s id stays, disabled');
        self::assertNull($graph->database()->findOne('auth_refresh_tokens', ['user_id' => $guest['user']['id'], 'revoked_at' => null]), 'the guest\'s sessions ended');
        $this->refused(fn() => $guests->convert($guest['user']['id'], $session->accessToken), AnonymousException::NOT_A_GUEST, 'once');

        $graph->tokens()->revokeFamily($session->sessionId, 'logout');
        $this->refused(fn() => $guests->convert($other['user']['id'], $session->accessToken), AnonymousException::TOKEN_INVALID, 'the account\'s session ended');
    }

    public function testAFailingHookConvertsNothing(): void
    {
        $graph = $this->polaris(new AnonymousPlugin(static function (): void {
            throw new RuntimeException('the host could not move the data');
        }))->graph();
        $guests = $graph->get(Guests::class);
        $guest = $guests->signIn($this->client);
        $ada = $this->user($graph, 'ada@example.com');
        $session = $graph->tokens()->issue(new SessionPrincipal($ada->id), $this->client);

        try {
            $guests->convert($guest['user']['id'], $session->accessToken);
            self::fail('the hook failed');
        } catch (RuntimeException) {
            self::assertNull($graph->database()->findOne(Schema::GUESTS, ['user_id' => $guest['user']['id']])['converted_at'] ?? null);
            self::assertSame(User::STATUS_ACTIVE, $graph->users()->find($guest['user']['id'])?->status);
            self::assertTrue($graph->get(Guests::class)->isGuest($guest['user']['id']));
            self::assertNotNull($graph->database()->findOne('auth_refresh_tokens', ['user_id' => $guest['user']['id'], 'revoked_at' => null]), 'the guest keeps its session to retry');
        }
    }

    public function testPruneDeletesTheUnconvertedGuestsOlderThanThePolicy(): void
    {
        $graph = $this->polaris()->graph();
        $guests = $graph->get(Guests::class);
        $old = $guests->signIn($this->client);
        $kept = $guests->signIn($this->client);
        $ada = $this->user($graph, 'ada@example.com');
        $guests->convert($kept['user']['id'], $graph->tokens()->issue(new SessionPrincipal($ada->id), $this->client)->accessToken);
        $this->clock->advance('+31 days');
        $recent = $guests->signIn($this->client);

        $tester = new CommandTester(AnonymousPlugin::of($graph)->commands($graph)[0]);
        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString('Pruned 1 guest(s).', $tester->getDisplay());
        $graph->identities()->clear();
        self::assertNull($graph->users()->find($old['user']['id']), 'gone with its core rows');
        self::assertSame(0, $graph->database()->count('auth_refresh_tokens', ['user_id' => $old['user']['id']]));
        self::assertFalse($guests->isGuest($old['user']['id']));
        self::assertTrue($guests->isGuest($kept['user']['id']), 'a converted guest stays for the host');
        self::assertTrue($guests->isGuest($recent['user']['id']), 'younger than the policy');
        self::assertSame([$old['user']['id']], [$this->events->ofType(UserDeleted::class)[0]->userId]);
        self::assertSame(0, $guests->prune());

        $bare = new CommandTester(new PruneCommand());
        self::assertSame(Command::INVALID, $bare->execute([]), 'no application, no policy');
    }

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, string $reason, string $message = ''): void
    {
        try {
            $call();
            self::fail($message === '' ? 'expected ' . $reason : $message);
        } catch (AnonymousException $exception) {
            self::assertSame($reason, $exception->reason, $message);
        }
    }

    private function user(Graph $graph, string $email): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->emailVerifiedAt = $this->clock->now();
        $user->createdAt = $user->updatedAt = $this->clock->now();
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    private function polaris(?AnonymousPlugin $plugin = null): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: $this->clock,
            dispatcher: $this->events,
            plugins: [$plugin ?? new AnonymousPlugin(function (string $guestId, string $userId): void {
                $this->converted[] = [$guestId, $userId];
            })],
        ));
    }
}

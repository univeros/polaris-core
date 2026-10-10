<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Tests;

use DateTimeImmutable;
use Laminas\Diactoros\ServerRequestFactory;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\ApiKeys\ApiKeyException;
use Polaris\ApiKeys\ApiKeysPlugin;
use Polaris\ApiKeys\AuditNames;
use Polaris\ApiKeys\Event\ApiKeyEvent;
use Polaris\ApiKeys\Http\ApiKeyMiddleware;
use Polaris\ApiKeys\Http\ApiKeyResolver;
use Polaris\ApiKeys\Http\Responses;
use Polaris\ApiKeys\IssuedKey;
use Polaris\ApiKeys\Keys;
use Polaris\ApiKeys\Model\ApiKey;
use Polaris\ApiKeys\Schema;
use Polaris\ApiKeys\Settings;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Authorization\Gate;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\MemberRemoved;
use Polaris\Event\UserDeleted;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_unshift;
use function sort;
use function str_repeat;
use function substr;

use const DATE_ATOM;

/**
 * The plugin wired through `Polaris::create()`, and the key service: minting, the secret shown once,
 * authentication with revocation, expiry and the rotation grace, the permission bound, the limits, the
 * resolver's token and the listeners. Separate processes: the schema registry is static.
 */
#[CoversClass(ApiKeysPlugin::class)]
#[CoversClass(Settings::class)]
#[CoversClass(Schema::class)]
#[CoversClass(Keys::class)]
#[CoversClass(IssuedKey::class)]
#[CoversClass(ApiKey::class)]
#[CoversClass(ApiKeyException::class)]
#[CoversClass(ApiKeyEvent::class)]
#[CoversClass(ApiKeyResolver::class)]
#[CoversClass(ApiKeyMiddleware::class)]
#[CoversClass(Responses::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-10T10:00:00+00:00';

    private MutableClock $clock;
    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $this->events = new RecordingEventDispatcher();
    }

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();

        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[] = $model->table;
        }
        self::assertContains(Schema::KEYS, $tables);
        $routes = [];
        foreach ($graph->manifest()->endpoints() as $spec) {
            if ($spec->plugin === ApiKeysPlugin::ID) {
                $routes[] = $spec->route();
            }
        }
        self::assertSame(['DELETE /api-keys/{id}', 'GET /api-keys', 'GET /api-keys/{id}', 'PATCH /api-keys/{id}', 'POST /api-keys', 'POST /api-keys/verify', 'POST /api-keys/{id}/rotate'], self::sorted($routes));
        self::assertInstanceOf(ApiKeyResolver::class, $graph->bearerResolvers()[0]);
        self::assertInstanceOf(ApiKeyMiddleware::class, ApiKeysPlugin::of($graph)->middleware($graph)[0]);
        $polaris->listeners();
        self::assertTrue($graph->get(Catalog::class)->has(AuditNames::CREATED), 'the names join the catalog when the listeners are wired');
        self::assertSame(Settings::LIVE, ApiKeysPlugin::of($graph)->settings()->environment);
    }

    public function testTheSettingsAreValidated(): void
    {
        self::assertSame('pk_test_', Settings::prefix(Settings::TEST));
        $this->expectException(LogicException::class);
        new Settings('staging');
    }

    public function testTheAuditPluginIsRequired(): void
    {
        $this->expectException(LogicException::class);
        $this->polaris(audit: false)->listeners();
    }

    public function testAKeyIsMintedOnceAuthenticatedWhileLiveAndBoundedByTheOwner(): void
    {
        $graph = $this->polaris()->graph();
        $keys = $graph->get(Keys::class);
        $user = self::user($graph);

        $issued = $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, '  CI  ', ['org.read'], ['org.read', 'members.read'], null, ['window' => 60, 'max' => 5], null, ['team' => 'infra']);
        self::assertStringStartsWith('pk_live_', $issued->secret);
        self::assertSame('CI', $issued->key->name);
        self::assertSame(substr($issued->secret, -4), $issued->key->hint);
        self::assertNotSame($issued->secret, $issued->key->keyHash);
        self::assertSame(['window' => 60, 'max' => 5], $issued->key->rateLimit());
        self::assertSame(['team' => 'infra'], $issued->key->metadata);

        $authenticated = $keys->authenticate($issued->secret);
        self::assertInstanceOf(ApiKey::class, $authenticated);
        self::assertSame($issued->key->id, $authenticated->id);
        self::assertSame(self::NOW, $authenticated->lastUsedAt?->format(DATE_ATOM), 'the use is stamped');
        self::assertNull($keys->authenticate('pk_live_' . str_repeat('x', 43)), 'unknown');
        self::assertNull($keys->authenticate('not a key'));

        $this->refused(fn() => $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'x', ['members.invite'], ['org.read']), ApiKeyException::PERMISSION_NOT_HELD);
        $this->refused(fn() => $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'x', ['not.a.permission'], ['not.a.permission']), ApiKeyException::INVALID_INPUT);
        $this->refused(fn() => $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, str_repeat('n', 81), [], []), ApiKeyException::INVALID_INPUT);
        $this->refused(fn() => $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'x', [], [], 'staging'), ApiKeyException::INVALID_INPUT);
        $this->refused(fn() => $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'x', [], [], null, ['window' => 60]), ApiKeyException::INVALID_INPUT);
        $this->refused(fn() => $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'x', [], [], null, null, $this->clock->now()), ApiKeyException::INVALID_INPUT, 'expiry in the past');
        $this->refused(fn() => $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'x', [], [], null, null, null, ['a', 'b']), ApiKeyException::INVALID_INPUT, 'metadata must be an object');
    }

    public function testExpiryRotationGraceAndRevocationEndAKey(): void
    {
        $graph = $this->polaris(rotationGrace: 600)->graph();
        $keys = $graph->get(Keys::class);
        $user = self::user($graph);

        $expiring = $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'expiring', [], [], null, null, $this->clock->now()->modify('+1 hour'));
        $rotating = $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'rotating', [], []);
        $successor = $keys->rotate($rotating->key);
        self::assertSame($rotating->key->id, $successor->key->rotatedFromId);
        self::assertSame(ApiKey::STATUS_ROTATED, $rotating->key->status($this->clock->now()));
        self::assertNotNull($keys->authenticate($rotating->secret), 'the predecessor answers during the grace');
        self::assertNotNull($keys->authenticate($successor->secret));

        $this->clock->advance('+10 minutes');
        self::assertNull($keys->authenticate($rotating->secret), 'the grace ended');
        self::assertNotNull($keys->authenticate($successor->secret));
        self::assertNotNull($keys->authenticate($expiring->secret));
        $this->clock->advance('+1 hour');
        self::assertNull($keys->authenticate($expiring->secret), 'expired');
        self::assertSame(ApiKey::STATUS_EXPIRED, $keys->find($expiring->key->id)?->status($this->clock->now()));

        $keys->revoke($successor->key);
        self::assertNull($keys->authenticate($successor->secret));
        self::assertSame([], array_filter($keys->forOwner(ApiKey::OWNER_USER, $user->id), static fn(ApiKey $k): bool => $k->revokedAt !== null), 'revoked keys leave the list');
        self::assertSame(ApiKey::STATUS_REVOKED, $keys->find($successor->key->id)?->status($this->clock->now()));

        $changes = $keys->update($expiring->key, ['org.read'], name: 'renamed', permissions: ['org.read'], rateLimit: null, expiresAt: null, metadata: ['k' => 'v']);
        self::assertSame(['name', 'permissions', 'rate_limit', 'expires_at', 'metadata'], $changes);
        self::assertSame([], $keys->update($expiring->key, []));
        self::assertNotNull($keys->authenticate($expiring->secret), 'the expiry was cleared');
    }

    public function testAnOwnerIsBoundedInKeysAndAnErasedUserLeavesNone(): void
    {
        $polaris = $this->polaris(maxPerOwner: 2);
        $graph = $polaris->graph();
        $keys = $graph->get(Keys::class);
        $user = self::user($graph);
        $this->events->listen(...$polaris->listeners());

        $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'one', [], []);
        $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'two', [], []);
        $this->refused(fn() => $keys->create(ApiKey::OWNER_USER, $user->id, null, $user->id, 'three', [], []), ApiKeyException::TOO_MANY);
        $keys->create(ApiKey::OWNER_ORGANIZATION, 'org-1', 'org-1', $user->id, 'org key', [], []);
        self::assertCount(2, $keys->forOwner(ApiKey::OWNER_USER, $user->id));

        $this->events->dispatch(new MemberRemoved('org-1', $user->id, 'admin-1'));
        self::assertSame([], $keys->forOwner(ApiKey::OWNER_ORGANIZATION, 'org-1'), 'a member who leaves takes the organization keys they act for');
        self::assertCount(2, $keys->forOwner(ApiKey::OWNER_USER, $user->id), 'their own keys stay');
        $keys->create(ApiKey::OWNER_ORGANIZATION, 'org-1', 'org-1', $user->id, 'org key again', [], []);
        $this->events->dispatch(new UserDeleted($user->id, 'admin-1'));
        self::assertSame([], $keys->forOwner(ApiKey::OWNER_USER, $user->id));
        self::assertSame([], $keys->forOwner(ApiKey::OWNER_ORGANIZATION, 'org-1'), 'the organization key the user acted for goes too');
    }

    public function testTheResolverAnswersTheOwnersTokenWithTheDelegatedPermissionsAndRefusesTheRest(): void
    {
        $graph = $this->polaris()->graph();
        $keys = $graph->get(Keys::class);
        $user = self::user($graph);
        $issued = $keys->create(ApiKey::OWNER_USER, $user->id, 'org-1', $user->id, 'CI', ['org.read'], ['org.read'], null, ['window' => 60, 'max' => 5]);
        $resolver = $graph->bearerResolvers()[0];

        self::assertNull($resolver->resolve(self::request()), 'nothing presented');
        self::assertNull($resolver->resolve(self::request()->withHeader('Authorization', 'Bearer eyJ.a.jwt')), 'a JWT is core\'s');
        $token = $resolver->resolve(self::request()->withHeader('Authorization', 'Bearer ' . $issued->secret));
        self::assertNotNull($token);
        self::assertSame([$user->id, 'org-1', $issued->key->id, ['api_key'], ['org.read'], ['window' => 60, 'max' => 5]], [
            $token->getMetadata('sub'), $token->getMetadata('org'), $token->getMetadata(ApiKeyResolver::CLAIM), $token->getMetadata('amr'), $token->getMetadata(Gate::DELEGATED), $token->getMetadata(ApiKeyResolver::RATE_LIMIT_CLAIM),
        ]);
        self::assertInstanceOf(DateTimeImmutable::class, $token->getMetadata('iat'));
        self::assertSame($issued->secret, ApiKeyResolver::presented(self::request()->withHeader('x-api-key', $issued->secret)));

        try {
            $resolver->resolve(self::request()->withHeader('x-api-key', 'pk_live_unknown'));
            self::fail('refused');
        } catch (AuthorizationTokenException) {
            self::addToAssertionCount(1);
        }
        $graph->database()->update('auth_users', ['id' => $user->id], ['status' => User::STATUS_DISABLED]);
        $graph->identities()->clear();
        try {
            $resolver->resolve(self::request()->withHeader('x-api-key', $issued->secret));
            self::fail('a disabled subject is refused');
        } catch (AuthorizationTokenException) {
            self::addToAssertionCount(1);
        }
    }

    private function polaris(bool $audit = true, int $rotationGrace = 86400, int $maxPerOwner = 50): Polaris
    {
        $keys = TestKeys::rsa();
        $plugins = [new ApiKeysPlugin(rotationGrace: $rotationGrace, maxPerOwner: $maxPerOwner)];
        if ($audit) {
            array_unshift($plugins, new AuditPlugin());
        }

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: $this->clock,
            dispatcher: $this->events,
            plugins: $plugins,
        ));
    }

    private static function user(Graph $graph): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = 'ada@example.com';
        $user->emailVerifiedAt = new DateTimeImmutable(self::NOW);
        $user->createdAt = new DateTimeImmutable(self::NOW);
        $user->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    private static function request(): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('GET', '/auth/me');
    }

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, string $reason, string $message = ''): void
    {
        try {
            $call();
            self::fail('refused: ' . $message);
        } catch (ApiKeyException $exception) {
            self::assertSame($reason, $exception->reason, $message . ' ' . $exception->detail);
        }
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private static function sorted(array $values): array
    {
        sort($values);

        return $values;
    }
}

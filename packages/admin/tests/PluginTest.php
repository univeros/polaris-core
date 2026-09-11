<?php

declare(strict_types=1);

namespace Polaris\Admin\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminAudit;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Console\GrantCommand;
use Polaris\Admin\Console\KeyCommand;
use Polaris\Admin\Grants;
use Polaris\Admin\Http\AdminMiddleware;
use Polaris\Admin\Impersonation;
use Polaris\Admin\Keys;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Principals;
use Polaris\Admin\Principal\Role;
use Polaris\Admin\Schema;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Cli\Application;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Schema\Schema as CoreSchema;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\SessionPrincipal;
use Polaris\Wiring\Config;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The plugin wired through `Polaris::create()`: its tables, routes, services, middleware and commands;
 * the principals it resolves. Separate processes: the schema registry is static.
 */
#[CoversClass(AdminPlugin::class)]
#[CoversClass(Keys::class)]
#[CoversClass(Grants::class)]
#[CoversClass(Principals::class)]
#[CoversClass(Impersonation::class)]
#[CoversClass(KeyCommand::class)]
#[CoversClass(GrantCommand::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-09-11T10:00:00+00:00';

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = self::polaris(new MutableClock(new DateTimeImmutable(self::NOW)));
        $graph = $polaris->graph();

        self::assertCount(20, $polaris->schema(), 'core, audit and the two admin tables');
        self::assertSame(Schema::KEYS, CoreSchema::for(\Polaris\Admin\Model\AdminKey::class)->table);
        $admin = 0;
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (in_array('admin', $spec->tags, true)) {
                ++$admin;
                self::assertSame('public', $spec->auth, $spec->file . ' leaves the bearer to the admin middleware');
                self::assertStringStartsWith('/admin/', $spec->path, $spec->file);
                $graph->endpoint($spec->class);
            }
        }
        self::assertSame(29, $admin);
        $middleware = $polaris->plugin(AdminPlugin::ID)->middleware($graph);
        self::assertInstanceOf(AdminMiddleware::class, $middleware[0]);
        self::assertTrue($graph->get(Catalog::class)->has(AdminAudit::USER_BANNED), 'the admin names joined the audit catalog');
        self::assertCount(5, $polaris->listeners(), 'core\'s three and audit\'s two; admin adds none');
    }

    public function testKeysAuthenticateByHashExpiryAndAllowlist(): void
    {
        $clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $keys = self::polaris($clock)->graph()->get(Keys::class);

        $issued = $keys->create('Dashboard', Role::Support, 'instance', ['10.0.0.0/8'], new DateTimeImmutable('2026-09-11T11:00:00+00:00'), 'cli');
        self::assertStringStartsWith(Keys::PREFIX, $issued->plaintext);
        self::assertNotSame($issued->plaintext, $issued->key->keyHash);
        self::assertArrayNotHasKey('key_hash', $issued->key->toArray(), 'the hash never leaves');

        $key = $keys->authenticate($issued->plaintext, '10.1.2.3');
        self::assertNotNull($key);
        self::assertSame($issued->key->id, $key->id);
        self::assertSame(self::NOW, $keys->find($key->id)?->lastUsedAt?->format(DATE_ATOM));
        self::assertNull($keys->authenticate($issued->plaintext, '192.168.1.1'), 'outside the allowlist');
        self::assertNull($keys->authenticate($issued->plaintext, null), 'no address, non-empty allowlist');
        self::assertNull($keys->authenticate(Keys::PREFIX . 'nope', '10.1.2.3'));
        self::assertNull($keys->authenticate('not-a-key', '10.1.2.3'));

        $clock->advance('+2 hours');
        self::assertNull($keys->authenticate($issued->plaintext, '10.1.2.3'), 'expired');
        self::assertTrue($keys->delete($key->id));
        self::assertFalse($keys->delete($key->id));
        self::assertSame([], $keys->all());
    }

    public function testGrantsAreOnePerUserAndLapse(): void
    {
        $clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $grants = self::polaris($clock)->graph()->get(Grants::class);

        $first = $grants->grant('u1', Role::Viewer);
        $second = $grants->grant('u1', Role::Admin, 'org-a', new DateTimeImmutable('2026-09-12T00:00:00+00:00'), 'k1');
        self::assertSame($first->id, $second->id, 'a new grant replaces the previous one');
        self::assertSame(['admin', 'org-a', 'k1'], [$second->role, $second->scope, $second->grantedBy]);
        self::assertCount(1, $grants->all());
        self::assertSame('admin', $grants->forUser('u1')?->role);

        $clock->advance('+1 day');
        self::assertNull($grants->forUser('u1'), 'lapsed');
        self::assertNotNull($grants->find($first->id), 'still listed until revoked');
        self::assertTrue($grants->revoke($first->id));
        self::assertSame([], $grants->all());
    }

    public function testPrincipalsResolveKeysGrantsAndRefuseImpersonationTokens(): void
    {
        $polaris = self::polaris(new MutableClock(new DateTimeImmutable(self::NOW)));
        $graph = $polaris->graph();
        $principals = $graph->get(Principals::class);
        $user = new User();
        $user->id = 'u1';
        $user->email = 'ada@example.com';
        $user->createdAt = $user->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();
        $session = $graph->tokens()->mint(new SessionPrincipal('u1'), 'sid-1');

        self::assertNull($principals->resolve(null, null)->principal);
        self::assertNull($principals->resolve('garbage', null)->principal);
        self::assertNull($principals->resolve($session, null)->principal, 'a plain user is no operator');

        $graph->get(Grants::class)->grant('u1', Role::Support, 'org-a');
        $resolved = $principals->resolve($session, '127.0.0.1')->principal;
        self::assertSame(['id' => 'u1', 'type' => 'user', 'role' => 'support', 'scope' => 'org-a'], $resolved?->toArray());

        $key = $graph->get(Keys::class)->create('ci', Role::Viewer);
        self::assertSame(Principal::TYPE_API_KEY, $principals->resolve($key->plaintext, null)->principal?->type);

        $impersonation = $graph->get(Impersonation::class)->start('u1', new Principal('k1', Principal::TYPE_API_KEY, Role::Admin));
        $claims = $graph->tokenFactory()->fromTokenString($impersonation['access_token'])->getMetadata();
        self::assertSame(['u1', 'k1', 'api_key', ['impersonation'], false], [$claims['sub'], $claims['impersonated_by'], $claims['impersonator_type'], $claims['amr'], $claims['mfa']]);
        self::assertArrayNotHasKey('sid', $claims, 'no session behind it');
        self::assertSame('Bearer', $impersonation['token_type']);
        $refused = $principals->resolve($impersonation['access_token'], null);
        self::assertNull($refused->principal);
        self::assertTrue($refused->impersonated);

        $user->status = User::STATUS_DISABLED;
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();
        self::assertNull($principals->resolve($session, null)->principal, 'a disabled operator is no operator');
    }

    public function testTheCommandsRunOnTheApplicationsGraph(): void
    {
        $polaris = self::polaris(new MutableClock(new DateTimeImmutable(self::NOW)));
        $graph = $polaris->graph();
        $user = new User();
        $user->id = 'u1';
        $user->email = 'ada@example.com';
        $user->createdAt = $user->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();
        $app = new Application($polaris);
        $app->setAutoExit(false);

        $key = new CommandTester($app->find('admin:key'));
        self::assertSame(0, $key->execute(['name' => 'Dashboard', 'role' => 'owner', '--allow' => '10.0.0.0/8, 203.0.113.7']));
        self::assertMatchesRegularExpression('/^pak_[A-Za-z0-9_-]{43}$/m', $key->getDisplay());
        self::assertSame(['10.0.0.0/8', '203.0.113.7'], $graph->get(Keys::class)->all()[0]->allowlist());
        self::assertSame(2, $key->execute(['name' => 'x', 'role' => 'root']));
        self::assertSame(2, $key->execute(['name' => 'x', 'role' => 'viewer', '--allow' => 'nowhere']));

        $grant = new CommandTester($app->find('admin:grant'));
        self::assertSame(0, $grant->execute(['email' => 'ada@example.com', 'role' => 'support', '--expires' => '2027-01-01T00:00:00+00:00']));
        self::assertStringContainsString('Granted support to ada@example.com', $grant->getDisplay());
        self::assertSame('2027-01-01T00:00:00+00:00', $graph->get(Grants::class)->forUser('u1')?->expiresAt?->format(DATE_ATOM));
        self::assertSame(1, $grant->execute(['email' => 'nobody@example.com', 'role' => 'support']));
    }

    private static function polaris(MutableClock $clock): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: $clock,
            plugins: [new AuditPlugin(), new AdminPlugin()],
        ));
    }
}

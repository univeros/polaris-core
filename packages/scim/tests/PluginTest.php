<?php

declare(strict_types=1);

namespace Polaris\Scim\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\MemberJoined;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Schema\Schema as CoreSchema;
use Polaris\Scim\AuditNames;
use Polaris\Scim\Connections;
use Polaris\Scim\Filter;
use Polaris\Scim\Groups;
use Polaris\Scim\Http\ScimMiddleware;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Patch;
use Polaris\Scim\Resources;
use Polaris\Scim\Schema;
use Polaris\Scim\ScimError;
use Polaris\Scim\ScimPlugin;
use Polaris\Scim\Users;
use Polaris\Sso\SsoPlugin;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\SessionPrincipal;
use Polaris\Wiring\Config;

use function array_column;
use function in_array;
use function str_starts_with;

/**
 * The plugin wired through `Polaris::create()`, the connections and their tokens, the users and groups
 * projected onto members and roles. Separate processes: the schema registry is static.
 */
#[CoversClass(ScimPlugin::class)]
#[CoversClass(Connections::class)]
#[CoversClass(Resources::class)]
#[CoversClass(Users::class)]
#[CoversClass(Groups::class)]
#[CoversClass(ScimMiddleware::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-09-12T10:00:00+00:00';
    private const string BASE = 'https://app.example/auth';
    private const string LOCATION = 'https://app.example/auth/scim/v2/c1';

    public function testEverythingIsWiredAndConnectionsAuthenticateByToken(): void
    {
        $polaris = self::polaris();
        $graph = $polaris->graph();

        self::assertCount(25, $polaris->schema(), 'core, audit, admin, sso and the three scim tables');
        self::assertSame(Schema::CONNECTIONS, CoreSchema::for(Connection::class)->table);
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (!in_array('scim', $spec->tags, true) && !in_array('scim-admin', $spec->tags, true)) {
                continue;
            }
            $graph->endpoint($spec->class);
            $routes[] = $spec->method . ' ' . $spec->path;
            if (str_starts_with($spec->path, '/scim/')) {
                self::assertSame('public', $spec->auth, $spec->file);
            } elseif (str_starts_with($spec->path, '/orgs/')) {
                self::assertSame(['bearer', ['org.update']], [$spec->auth, $spec->requiresPermissions], $spec->file);
            }
        }
        self::assertCount(22, $routes);
        self::assertInstanceOf(ScimMiddleware::class, $polaris->plugin(ScimPlugin::ID)->middleware($graph)[0]);
        foreach (AuditNames::ALL as $name => $description) {
            self::assertTrue($graph->get(Catalog::class)->has($name), $name);
        }

        $connections = $graph->get(Connections::class);
        [$connection, $token] = $connections->create('org-1', 'Okta', Connection::DELETE, null, 'u1');
        self::assertStringStartsWith('pst_', $token);
        self::assertNotSame($token, $connection->tokenHash);
        self::assertSame(['Okta', 'active', 'delete'], [$connection->name, $connection->status, $connection->deprovision()]);
        self::assertArrayNotHasKey('token_hash', $connection->toArray());
        self::assertSame($connection->id, $connections->authenticate($token)?->id);
        self::assertNull($connections->authenticate('pst_nope'));
        self::assertNull($connections->authenticate('not a token'));
        self::assertNull($connections->authenticate(null));
        $rotated = $connections->rotate($connection);
        self::assertNull($connections->authenticate($token), 'the previous token stopped');
        self::assertSame($connection->id, $connections->authenticate($rotated)?->id);
        $connections->create('org-2', 'Entra', Connection::DEACTIVATE, null, null);
        self::assertCount(1, $connections->forOrganization('org-1'));
        $page = $connections->list(limit: 1);
        self::assertNotNull($page['next_cursor']);
        self::assertCount(1, $connections->list(cursor: $page['next_cursor'])['data']);
        $connections->decommission($connection);
        self::assertNull($connections->authenticate($rotated), 'decommissioned');
        self::assertSame('decommissioned', $connections->find($connection->id)?->status);
        self::assertTrue($connections->delete($connection->id));
        self::assertFalse($connections->delete($connection->id));
    }

    public function testUsersAreMembersProvisionedPatchedAndDeprovisioned(): void
    {
        $events = new RecordingEventDispatcher();
        $polaris = self::polaris($events);
        $graph = $polaris->graph();
        $events->listen(...$polaris->listeners());
        $organizationId = self::organization($polaris);
        [$connection] = $graph->get(Connections::class)->create($organizationId, 'Okta', Connection::DEACTIVATE, null, null);
        $users = $graph->get(Users::class);

        $ada = $users->create($connection, ['userName' => 'Ada@Acme.example', 'displayName' => 'Ada Lovelace', 'externalId' => 'ext-ada', 'emails' => [['value' => 'ada@acme.example', 'primary' => true]]]);
        self::assertSame(['ada@acme.example', 'Ada Lovelace', null, true], [$ada->email, $ada->displayName, $ada->passwordHash, $ada->emailVerifiedAt !== null]);
        $membership = $graph->database()->findOne('auth_memberships', ['user_id' => $ada->id, 'organization_id' => $organizationId]);
        self::assertSame('active', $membership['status'] ?? null);
        self::assertSame(1, $graph->database()->count('auth_membership_roles', ['membership_id' => $membership['id'] ?? '']), 'the member role');
        self::assertTrue($graph->get(Resources::class)->createdMembership($connection, $ada->id));
        self::assertCount(1, $events->ofType(MemberJoined::class));
        $resource = $users->resource($connection, $ada, self::LOCATION);
        self::assertSame([Users::SCHEMA], $resource['schemas']);
        self::assertSame(['ada@acme.example', 'ext-ada', true, self::LOCATION . '/Users/' . $ada->id], [$resource['userName'], $resource['externalId'], $resource['active'], $resource['meta']['location']]);
        self::assertSame(['Member'], array_column($resource['groups'], 'display'));

        $this->refused(fn() => $users->create($connection, ['userName' => 'owner@acme.example']), 409, 'the owner is a member already');
        $grace = new User();
        $grace->id = 'u-grace';
        $grace->email = 'grace@acme.example';
        $grace->createdAt = $grace->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($grace);
        $graph->unitOfWork()->flush();
        $owner = $users->create($connection, ['userName' => 'grace@acme.example', 'name' => ['givenName' => 'Grace', 'familyName' => 'Hopper']]);
        self::assertSame('u-grace', $owner->id, 'an existing account joins rather than duplicating');
        self::assertSame('Grace Hopper', $owner->displayName);
        self::assertTrue($graph->get(Resources::class)->createdMembership($connection, $owner->id), 'the membership is the connection\'s');
        $graph->get(Resources::class)->forgetMembership($connection, $owner->id);
        $this->refused(fn() => $users->create($connection, ['userName' => 'ada@acme.example']), 409);
        $this->refused(fn() => $users->create($connection, ['userName' => 'not-an-email']), 400);
        $this->refused(fn() => $users->find($connection, 'nope'), 404);

        $page = $users->list($connection, Filter::parse('userName eq "ADA@acme.example"'), 1, 10, self::LOCATION);
        self::assertSame([1, 'ada@acme.example'], [$page['total'], $page['resources'][0]['userName']]);
        self::assertSame(1, $users->list($connection, Filter::parse('externalId eq "ext-ada"'), 1, 10, self::LOCATION)['total']);
        $all = $users->list($connection, Filter::parse(null), 3, 1, self::LOCATION);
        self::assertSame([3, 1], [$all['total'], count($all['resources'])], 'startIndex 3 of 3');

        $patched = $users->patch($connection, $ada, Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]]]));
        self::assertSame(User::STATUS_DISABLED, $patched->status);
        $patched = $users->patch($connection, $patched, Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'replace', 'value' => ['active' => 'True', 'name' => ['givenName' => 'Ada', 'familyName' => 'King'], 'externalId' => 'ext-2']]]]));
        self::assertSame([User::STATUS_ACTIVE, 'Ada King', 'ext-2'], [$patched->status, $patched->displayName, $graph->get(Resources::class)->externalId($connection, 'User', $ada->id)]);
        $patched = $users->patch($connection, $patched, Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'replace', 'path' => 'userName', 'value' => 'ada.king@acme.example'], ['op' => 'remove', 'path' => 'externalId']]]));
        self::assertSame(['ada.king@acme.example', null], [$patched->email, $graph->get(Resources::class)->externalId($connection, 'User', $ada->id)]);
        $this->refused(fn() => $users->patch($connection, $patched, Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'replace', 'path' => 'userName', 'value' => 'grace@acme.example']]])), 409, 'another account\'s email');
        $replaced = $users->replace($connection, $patched, ['userName' => 'ada@acme.example', 'displayName' => 'Ada', 'active' => false, 'externalId' => 'ext-3']);
        self::assertSame(['ada@acme.example', 'Ada', User::STATUS_DISABLED, 'ext-3'], [$replaced->email, $replaced->displayName, $replaced->status, $graph->get(Resources::class)->externalId($connection, 'User', $ada->id)]);

        self::assertSame('deactivated', $users->delete($connection, $replaced));
        self::assertNull($graph->database()->findOne('auth_memberships', ['user_id' => $ada->id, 'organization_id' => $organizationId]), 'the membership the connection created is gone');
        self::assertSame(User::STATUS_DISABLED, $graph->users()->find($ada->id)?->status);
        self::assertSame('deactivated', $users->delete($connection, $owner));
        self::assertNotNull($graph->database()->findOne('auth_memberships', ['user_id' => $owner->id, 'organization_id' => $organizationId]), 'a membership the connection did not create stays');
        [$deleting] = $graph->get(Connections::class)->create($organizationId, 'Purge', Connection::DELETE, null, null);
        $bob = $users->create($deleting, ['userName' => 'bob@acme.example']);
        self::assertSame('deleted', $users->delete($deleting, $bob));
        self::assertNotSame('bob@acme.example', $graph->users()->find($bob->id)?->email, 'anonymised');
    }

    public function testGroupsAreRolesWithMembers(): void
    {
        $polaris = self::polaris();
        $graph = $polaris->graph();
        $organizationId = self::organization($polaris);
        [$connection] = $graph->get(Connections::class)->create($organizationId, 'Okta', Connection::DEACTIVATE, null, null);
        $users = $graph->get(Users::class);
        $groups = $graph->get(Groups::class);
        $ada = $users->create($connection, ['userName' => 'ada@acme.example']);
        $bob = $users->create($connection, ['userName' => 'bob@acme.example']);

        $engineering = $groups->create($connection, ['displayName' => 'Engineering Team', 'externalId' => 'g-1', 'members' => [['value' => $ada->id]]]);
        self::assertSame(['Engineering Team', 'engineering-team', $organizationId], [$engineering['name'], $engineering['slug'], $engineering['organization_id']]);
        $resource = $groups->resource($connection, $engineering, self::LOCATION);
        self::assertSame([[Groups::SCHEMA], 'g-1', [$ada->id]], [$resource['schemas'], $resource['externalId'], array_column($resource['members'], 'value')]);
        self::assertContains('Engineering Team', array_column($users->resource($connection, $ada, self::LOCATION)['groups'], 'display'));
        $this->refused(fn() => $groups->create($connection, ['displayName' => 'Engineering Team']), 409);
        $this->refused(fn() => $groups->create($connection, ['displayName' => '']), 400);
        $this->refused(fn() => $groups->create($connection, ['displayName' => 'Ops', 'members' => [['value' => 'nobody']]]), 400, 'not a member');

        $listed = $groups->list($connection, Filter::parse('displayName co "engineering"'), 1, 10, self::LOCATION);
        self::assertSame([1, (string) $engineering['id']], [$listed['total'], $listed['resources'][0]['id']]);
        self::assertGreaterThanOrEqual(4, $groups->list($connection, Filter::parse(null), 1, 10, self::LOCATION)['total'], 'the system roles too');

        $patched = $groups->patch($connection, $engineering, Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'add', 'path' => 'members', 'value' => [['value' => $bob->id]]], ['op' => 'replace', 'path' => 'displayName', 'value' => 'Engineering']]]));
        self::assertSame(['Engineering', [$ada->id, $bob->id]], [$patched['name'], self::sorted(array_column($groups->resource($connection, $patched, self::LOCATION)['members'], 'value'))]);
        $patched = $groups->patch($connection, $patched, Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'remove', 'path' => 'members[value eq "' . $ada->id . '"]']]]));
        self::assertSame([$bob->id], array_column($groups->resource($connection, $patched, self::LOCATION)['members'], 'value'));
        $replaced = $groups->replace($connection, $patched, ['displayName' => 'Engineering', 'members' => [['value' => $ada->id]]]);
        self::assertSame([$ada->id], array_column($groups->resource($connection, $replaced, self::LOCATION)['members'], 'value'));
        $this->refused(fn() => $groups->patch($connection, $replaced, Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'add', 'path' => 'members[value eq "x"]', 'value' => []]]])), 400);

        $member = $graph->database()->findOne('auth_roles', ['organization_id' => $organizationId, 'slug' => 'member']);
        self::assertNotNull($member);
        $this->refused(fn() => $groups->replace($connection, $member, ['displayName' => 'Renamed']), 403, 'a built-in role keeps its name');
        $this->refused(fn() => $groups->delete($connection, $member), 403);
        $groups->replace($connection, $member, ['displayName' => (string) $member['name'], 'members' => [['value' => $bob->id]]]);
        self::assertSame([$bob->id], array_column($groups->resource($connection, $member, self::LOCATION)['members'], 'value'), 'a built-in role takes members');
        $groups->delete($connection, $replaced);
        $this->refused(fn() => $groups->find($connection, (string) $replaced['id']), 404);
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

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, int $status, string $message = ''): void
    {
        try {
            $call();
            self::fail($message === '' ? 'expected ' . $status : $message);
        } catch (ScimError $error) {
            self::assertSame($status, $error->status, $message);
        }
    }

    private static function organization(Polaris $polaris): string
    {
        $graph = $polaris->graph();
        $owner = new User();
        $owner->id = 'u-owner';
        $owner->email = 'owner@acme.example';
        $owner->createdAt = $owner->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($owner);
        $graph->unitOfWork()->flush();

        return $graph->organizations()->create('Acme', null, $owner->id)->id;
    }

    private static function polaris(?RecordingEventDispatcher $events = null): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: new MutableClock(new DateTimeImmutable(self::NOW)),
            dispatcher: $events,
            plugins: [new AuditPlugin(), new AdminPlugin(), new SsoPlugin(self::BASE), new ScimPlugin(self::BASE)],
        ));
    }
}

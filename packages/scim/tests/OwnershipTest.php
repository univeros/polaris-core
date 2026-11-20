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
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Model\Membership;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Scim\Connections;
use Polaris\Scim\Groups;
use Polaris\Scim\Model\Connection;
use Polaris\Scim\Owners;
use Polaris\Scim\Patch;
use Polaris\Scim\ScimError;
use Polaris\Scim\ScimPlugin;
use Polaris\Scim\Users;
use Polaris\Sso\Domains;
use Polaris\Sso\SsoPlugin;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;

/**
 * A directory belongs to one organization, an account is global: a connection writes an account's
 * email, name and status only when it created the account and the account belongs to no other
 * organization; any other account is changed through its membership in the connection's organization.
 * Separate processes: the schema registry is static.
 */
#[CoversClass(Users::class)]
#[CoversClass(Groups::class)]
#[CoversClass(Owners::class)]
#[RunTestsInSeparateProcesses]
final class OwnershipTest extends TestCase
{
    private const string NOW = '2026-11-20T10:00:00+00:00';
    private const string BASE = 'https://app.example/auth';

    public function testADirectoryCannotClaimAnotherOrganizationsAccount(): void
    {
        [$polaris, $connection, $victim] = self::tenants();
        $graph = $polaris->graph();

        $this->refused(fn() => $graph->get(Users::class)->create($connection, ['userName' => $victim->email, 'displayName' => 'Pwned']), 409, 'an existing account on a domain the organization did not verify');
        self::assertNull(self::membership($polaris, $victim->id, $connection->organizationId), 'the victim was not joined to the organization');
        self::assertNull($graph->users()->find($victim->id)?->displayName, 'the victim\'s profile is untouched');
    }

    public function testADirectoryCannotRenameDisableOrEraseAnAccountItDoesNotOwn(): void
    {
        [$polaris, $connection, $victim, $other] = self::tenants();
        $graph = $polaris->graph();
        $users = $graph->get(Users::class);
        self::verify($polaris, $connection->organizationId, 'victim.example');

        $linked = $users->create($connection, ['userName' => $victim->email, 'displayName' => 'Pwned']);
        self::assertSame([$victim->id, null], [$linked->id, $linked->displayName], 'an account of a verified domain joins with its profile untouched');

        $this->refused(fn() => $users->patch($connection, $linked, self::ops(['op' => 'replace', 'path' => 'userName', 'value' => 'attacker@evil.example'])), 403, 'PATCH userName of an account the directory does not own');
        $this->refused(fn() => $users->replace($connection, $linked, ['userName' => 'attacker@evil.example']), 403, 'PUT userName of an account the directory does not own');
        $patched = $users->patch($connection, $linked, self::ops(['op' => 'replace', 'value' => ['displayName' => 'Pwned', 'active' => false]]));
        self::assertSame([$victim->email, null, User::STATUS_ACTIVE], [$patched->email, $patched->displayName, $patched->status], 'the account is unchanged');
        self::assertSame(Membership::STATUS_SUSPENDED, self::membership($polaris, $victim->id, $connection->organizationId)['status'] ?? null, 'active false suspends the membership');
        self::assertSame(Membership::STATUS_ACTIVE, self::membership($polaris, $victim->id, $other)['status'] ?? null, 'the victim\'s own organization is untouched');
        self::assertFalse($users->resource($connection, $patched, self::BASE)['active']);

        [$deleting] = $graph->get(Connections::class)->create($connection->organizationId, 'Purge', Connection::DELETE, null, null);
        self::assertSame('deleted', $users->delete($deleting, $patched));
        $after = $graph->users()->find($victim->id);
        self::assertSame([$victim->email, User::STATUS_ACTIVE], [$after?->email, $after?->status], 'deprovision=delete neither erased nor disabled the account');
        self::assertNull(self::membership($polaris, $victim->id, $connection->organizationId), 'the membership is gone');
    }

    public function testAnAccountTheDirectoryCreatedIsNoLongerItsOnceItJoinsAnotherOrganization(): void
    {
        [$polaris, $connection, , $other] = self::tenants();
        $graph = $polaris->graph();
        $users = $graph->get(Users::class);

        $bob = $users->create($connection, ['userName' => 'bob@acme.example']);
        $bob = $users->patch($connection, $bob, self::ops(['op' => 'replace', 'path' => 'userName', 'value' => 'robert@acme.example']));
        self::assertSame('robert@acme.example', $bob->email, 'the directory renames the account it created');
        $bob = $users->patch($connection, $bob, self::ops(['op' => 'replace', 'path' => 'active', 'value' => false]));
        self::assertSame(User::STATUS_ACTIVE, $bob->status, 'active false suspends the membership, even of an owned account');

        $graph->database()->insert('auth_memberships', ['id' => 'm-b', 'user_id' => $bob->id, 'organization_id' => $other, 'status' => Membership::STATUS_ACTIVE, 'joined_at' => null, 'created_at' => new DateTimeImmutable(self::NOW), 'updated_at' => new DateTimeImmutable(self::NOW)]);
        $this->refused(fn() => $users->patch($connection, $bob, self::ops(['op' => 'replace', 'path' => 'userName', 'value' => 'attacker@evil.example'])), 403, 'the account belongs to another organization too');
    }

    public function testADirectoryNeverLeavesAnOrganizationWithoutAnActiveOwner(): void
    {
        $polaris = self::polaris();
        $graph = $polaris->graph();
        $organizationId = self::organization($polaris, 'u-owner', 'owner@acme.example', 'Acme');
        [$connection] = $graph->get(Connections::class)->create($organizationId, 'Okta', Connection::DEACTIVATE, null, null);
        self::verify($polaris, $organizationId, 'acme.example');
        $users = $graph->get(Users::class);
        $groups = $graph->get(Groups::class);
        $owner = $graph->users()->find('u-owner');
        self::assertInstanceOf(User::class, $owner);
        $ownerRole = $graph->database()->findOne('auth_roles', ['organization_id' => $organizationId, 'slug' => 'owner']);
        self::assertNotNull($ownerRole);

        $this->refused(fn() => $groups->patch($connection, $ownerRole, self::ops(['op' => 'replace', 'path' => 'members', 'value' => []])), 409, 'emptying the owner role');
        $this->refused(fn() => $groups->patch($connection, $ownerRole, self::ops(['op' => 'remove', 'path' => 'members[value eq "u-owner"]'])), 409, 'removing the last owner');
        $this->refused(fn() => $groups->replace($connection, $ownerRole, ['displayName' => (string) $ownerRole['name'], 'members' => []]), 409, 'PUT of the owner role without members');
        $this->refused(fn() => $users->patch($connection, $owner, self::ops(['op' => 'replace', 'path' => 'active', 'value' => false])), 409, 'suspending the last active owner');
        $this->refused(fn() => $users->delete($connection, $owner), 409, 'deprovisioning the last active owner');
        self::assertSame(1, $graph->database()->count('auth_membership_roles', ['role_id' => $ownerRole['id']]));
        self::assertSame(Membership::STATUS_ACTIVE, self::membership($polaris, 'u-owner', $organizationId)['status'] ?? null);

        $ada = $users->create($connection, ['userName' => 'ada@acme.example']);
        $groups->patch($connection, $ownerRole, self::ops(['op' => 'add', 'path' => 'members', 'value' => [['value' => $ada->id]]]));
        $groups->patch($connection, $ownerRole, self::ops(['op' => 'remove', 'path' => 'members[value eq "u-owner"]']));
        self::assertSame(1, $graph->database()->count('auth_membership_roles', ['role_id' => $ownerRole['id']]), 'another active owner takes over');
    }

    /**
     * Org A (owned by u-owner) with a directory, and the victim, owner of org B.
     *
     * @return array{Polaris, Connection, User, string}
     */
    private static function tenants(): array
    {
        $polaris = self::polaris();
        $graph = $polaris->graph();
        $organizationId = self::organization($polaris, 'u-owner', 'owner@acme.example', 'Acme');
        $other = self::organization($polaris, 'u-victim', 'victim@victim.example', 'Beta');
        [$connection] = $graph->get(Connections::class)->create($organizationId, 'Okta', Connection::DEACTIVATE, null, null);
        $victim = $graph->users()->find('u-victim');
        self::assertInstanceOf(User::class, $victim);

        return [$polaris, $connection, $victim, $other];
    }

    private static function verify(Polaris $polaris, string $organizationId, string $domain): void
    {
        $domains = $polaris->graph()->get(Domains::class);
        $domains->markVerified($domains->add($organizationId, 'p-1', $domain));
    }

    /**
     * @return list<array{string, string|null, mixed}>
     */
    private static function ops(array ...$operations): array
    {
        return Patch::operations(['schemas' => [Patch::SCHEMA], 'Operations' => $operations]);
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function membership(Polaris $polaris, string $userId, string $organizationId): ?array
    {
        return $polaris->graph()->database()->findOne('auth_memberships', ['user_id' => $userId, 'organization_id' => $organizationId]);
    }

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, int $status, string $message): void
    {
        try {
            $call();
            self::fail($message);
        } catch (ScimError $error) {
            self::assertSame($status, $error->status, $message . ': ' . $error->detail);
        }
    }

    private static function organization(Polaris $polaris, string $userId, string $email, string $name): string
    {
        $graph = $polaris->graph();
        $owner = new User();
        $owner->id = $userId;
        $owner->email = $email;
        $owner->createdAt = $owner->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($owner);
        $graph->unitOfWork()->flush();

        return $graph->organizations()->create($name, null, $owner->id)->id;
    }

    private static function polaris(): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: new MutableClock(new DateTimeImmutable(self::NOW)),
            plugins: [new AuditPlugin(), new AdminPlugin(), new SsoPlugin(self::BASE), new ScimPlugin(self::BASE)],
        ));
    }
}

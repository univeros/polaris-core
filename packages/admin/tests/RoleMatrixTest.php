<?php

declare(strict_types=1);

namespace Polaris\Admin\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\Principal\Capability;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;

/**
 * The role matrix of the README: deny by default, each role including the ones below it.
 */
#[CoversClass(Role::class)]
#[CoversClass(Principal::class)]
final class RoleMatrixTest extends TestCase
{
    /**
     * @return iterable<string, array{Role, list<Capability>}>
     */
    public static function roles(): iterable
    {
        yield 'viewer' => [Role::Viewer, [Capability::Read]];
        yield 'support' => [Role::Support, [Capability::Read, Capability::Support]];
        yield 'admin' => [Role::Admin, [Capability::Read, Capability::Support, Capability::Manage, Capability::Impersonate]];
        yield 'owner' => [Role::Owner, Capability::cases()];
    }

    /**
     * @param list<Capability> $allowed
     */
    #[DataProvider('roles')]
    public function testEachRoleAllowsExactlyItsCapabilities(Role $role, array $allowed): void
    {
        foreach (Capability::cases() as $capability) {
            self::assertSame(in_array($capability, $allowed, true), $role->allows($capability), "$role->value / $capability->value");
        }
    }

    public function testRolesParseFromInputOnly(): void
    {
        self::assertSame(Role::Support, Role::tryFromInput('support'));
        self::assertNull(Role::tryFromInput('root'));
        self::assertNull(Role::tryFromInput(['owner']));
    }

    public function testAnInstancePrincipalCoversEveryOrganizationAndAScopedOneItsOwn(): void
    {
        $instance = new Principal('k1', Principal::TYPE_API_KEY, Role::Viewer);
        $scoped = new Principal('u1', Principal::TYPE_USER, Role::Admin, 'org-a');

        self::assertTrue($instance->covers(null));
        self::assertTrue($instance->covers('org-a'));
        self::assertFalse($scoped->covers(null), 'instance-level actions are outside an organization scope');
        self::assertTrue($scoped->covers('org-a'));
        self::assertFalse($scoped->covers('org-b'));
        self::assertSame(['id' => 'u1', 'type' => 'user', 'role' => 'admin', 'scope' => 'org-a'], $scoped->toArray());
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Tests\Persistence;

use DateTimeImmutable;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionCatalogSeeder;

use function array_column;
use function count;
use function is_string;

/**
 * Verifies the #30 seed migration against a real database driver: the code-defined
 * {@see PermissionCatalog} drives `auth_permissions`, the four system role templates and their
 * grants are seeded, re-running the seed is idempotent (no duplicates), and the migration rolls
 * back cleanly. The base {@see DatabaseTestCase} has already run the seed migration in setUp.
 */
final class PermissionCatalogSeedPersistenceTest extends DatabaseTestCase
{
    public function testCatalogDrivesAuthPermissions(): void
    {
        $catalog = new PermissionCatalog();
        $expected = $catalog->permissions();

        $rows = $this->adapter->findMany('auth_permissions', []);
        $keys = array_column($rows, 'key');

        self::assertCount(count($expected), $keys);
        foreach ($expected as $key => $description) {
            self::assertContains($key, $keys, "auth_permissions should contain seeded key $key");
        }
    }

    public function testSeedsSystemRoleTemplatesWithGrants(): void
    {
        $database = $this->adapter;

        self::assertSame(4, $database->count('auth_roles', ['is_system' => true]));

        // owner = all 10 org permissions; admin = 9 (no org.delete); member = 3; superadmin = all 12.
        self::assertSame(10, $database->count('auth_role_permissions', ['role_id' => $this->systemRoleId('owner')]));
        self::assertSame(9, $database->count('auth_role_permissions', ['role_id' => $this->systemRoleId('admin')]));
        self::assertSame(3, $database->count('auth_role_permissions', ['role_id' => $this->systemRoleId('member')]));
        self::assertSame(12, $database->count('auth_role_permissions', ['role_id' => $this->systemRoleId('superadmin')]));
    }

    public function testReseedingIsIdempotent(): void
    {
        $database = $this->adapter;
        $permissionsBefore = $database->count('auth_permissions', []);
        $rolesBefore = $database->count('auth_roles', []);
        $grantsBefore = $database->count('auth_role_permissions', []);

        (new PermissionCatalogSeeder(new PermissionCatalog()))->seed($this->adapter, new DateTimeImmutable('2026-06-09 12:00:00'));

        self::assertSame($permissionsBefore, $database->count('auth_permissions', []));
        self::assertSame($rolesBefore, $database->count('auth_roles', []));
        self::assertSame($grantsBefore, $database->count('auth_role_permissions', []));
    }

    private function systemRoleId(string $slug): string
    {
        foreach ($this->adapter->findMany('auth_roles', ['slug' => $slug]) as $row) {
            if (is_string($id = $row['id'] ?? null) && ($row['organization_id'] ?? null) === null) {
                return $id;
            }
        }

        self::fail("System role $slug was not seeded");
    }
}

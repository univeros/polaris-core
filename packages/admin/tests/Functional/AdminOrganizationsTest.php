<?php

declare(strict_types=1);

namespace Polaris\Admin\Tests\Functional;

use Polaris\Admin\Principal\Role;

use function array_column;

final class AdminOrganizationsTest extends AdminTestCase
{
    public function testOrganizationsAreListedReadRolesSetAndDeleted(): void
    {
        $ada = $this->login('ada@example.com');
        $adaId = $this->userId('ada@example.com');
        $this->login('bob@example.com');
        $bobId = $this->userId('bob@example.com');
        $acme = $this->createOrg('Acme Rockets', $ada);
        $globex = $this->createOrg('Globex', $ada);
        $this->join('bob@example.com', $acme, 'member');
        $owner = $this->operator();

        $list = $this->json($this->authedGet('/admin/organizations', $owner));
        self::assertSame(['acme-rockets', 'globex'], array_column($list['data'], 'slug'));
        self::assertSame([$globex], array_column($this->json($this->authedGet('/admin/organizations?limit=1&cursor=' . $acme, $owner))['data'], 'id'));
        $this->problem($this->authedGet('/admin/organizations?status=gone', $owner), 422, 'admin_invalid_input');

        $read = $this->json($this->authedGet('/admin/organizations/' . $acme, $owner))['data'];
        self::assertSame('Acme Rockets', $read['name']);
        $members = array_column($read['members'], 'roles', 'email');
        self::assertSame(['ada@example.com' => ['owner'], 'bob@example.com' => ['member']], $members);
        $this->problem($this->authedGet('/admin/organizations/nope', $owner), 404, 'admin_not_found');

        $this->problem($this->authedPatch('/admin/organizations/' . $acme . '/members/' . $adaId . '/roles', ['roles' => ['admin']], $owner), 409, 'admin_conflict');
        $this->problem($this->authedPatch('/admin/organizations/' . $acme . '/members/' . $bobId . '/roles', ['roles' => ['ceo']], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPatch('/admin/organizations/' . $acme . '/members/' . $bobId . '/roles', ['roles' => []], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPatch('/admin/organizations/' . $globex . '/members/' . $bobId . '/roles', ['roles' => ['admin']], $owner), 404, 'admin_not_found');
        self::assertSame(['owner', 'admin'], $this->json($this->authedPatch('/admin/organizations/' . $acme . '/members/' . $bobId . '/roles', ['roles' => ['owner', 'admin']], $owner))['data']['roles']);
        self::assertSame(['admin'], $this->json($this->authedPatch('/admin/organizations/' . $acme . '/members/' . $adaId . '/roles', ['roles' => ['admin']], $owner))['data']['roles'], 'bob is an owner now, so ada can step down');
        $members = array_column($this->json($this->authedGet('/admin/organizations/' . $acme, $owner))['data']['members'], 'roles', 'email');
        self::assertSame(['ada@example.com' => ['admin'], 'bob@example.com' => ['owner', 'admin']], ['ada@example.com' => $members['ada@example.com'], 'bob@example.com' => array_values(array_intersect(['owner', 'admin'], $members['bob@example.com']))]);

        self::assertSame('suspended', $this->json($this->authedDelete('/admin/organizations/' . $globex, $owner))['data']['status']);
        self::assertSame([$globex], array_column($this->json($this->authedGet('/admin/organizations?status=suspended', $owner))['data'], 'id'));
        self::assertSame(['admin.organization_deleted', 'admin.member_roles_changed', 'admin.member_roles_changed'], array_column($this->json($this->authedGet('/admin/audit?names=admin.organization_deleted,admin.member_roles_changed', $owner))['data'], 'name'));
    }

    public function testAnOrganizationScopedPrincipalSeesItsOrganizationOnly(): void
    {
        $ada = $this->login('ada@example.com');
        $acme = $this->createOrg('Acme Rockets', $ada);
        $globex = $this->createOrg('Globex', $ada);
        $scoped = $this->key(Role::Admin, $acme);

        self::assertSame('Acme Rockets', $this->json($this->authedGet('/admin/organizations/' . $acme, $scoped))['data']['name']);
        $this->problem($this->authedGet('/admin/organizations/' . $globex, $scoped), 403, 'admin_forbidden');
        $this->problem($this->authedGet('/admin/organizations', $scoped), 403, 'admin_forbidden');
        $this->problem($this->authedGet('/admin/users', $scoped), 403, 'admin_forbidden');
        $this->problem($this->authedGet('/admin/stats', $scoped), 403, 'admin_forbidden');
        $this->problem($this->authedGet('/admin/keys', $scoped), 403, 'admin_forbidden');

        $trail = $this->json($this->authedGet('/admin/audit', $scoped))['data'];
        self::assertSame([$acme], array_unique(array_column($trail, 'organization_id')), 'the trail is the organization\'s');
        $this->problem($this->authedGet('/admin/audit?organization_id=' . $globex, $scoped), 403, 'admin_forbidden');

        $grantee = $this->operator(Role::Viewer, $globex);
        self::assertSame('Globex', $this->json($this->authedGet('/admin/organizations/' . $globex, $grantee))['data']['name']);
        $this->problem($this->authedGet('/admin/organizations/' . $acme, $grantee), 403, 'admin_forbidden');
    }

    public function testDrainsAreManagedPerOrganizationByOwners(): void
    {
        $ada = $this->login('ada@example.com');
        $acme = $this->createOrg('Acme Rockets', $ada);
        $owner = $this->operator();
        $admin = $this->key(Role::Admin);

        $this->problem($this->authedPostJson('/admin/organizations/' . $acme . '/drains', ['endpoint' => 'https://hooks.example.test/audit', 'secret' => 'a-secret-of-sixteen-chars'], $admin), 403, 'admin_forbidden');
        $this->problem($this->authedPostJson('/admin/organizations/' . $acme . '/drains', ['endpoint' => 'http://hooks.example.test/audit', 'secret' => 'a-secret-of-sixteen-chars'], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPostJson('/admin/organizations/' . $acme . '/drains', ['endpoint' => 'https://hooks.example.test/audit', 'secret' => 'short'], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPostJson('/admin/organizations/nope/drains', ['endpoint' => 'https://hooks.example.test/audit', 'secret' => 'a-secret-of-sixteen-chars'], $owner), 404, 'admin_not_found');

        $drain = $this->json($this->authedPostJson('/admin/organizations/' . $acme . '/drains', ['endpoint' => 'https://hooks.example.test/audit', 'secret' => 'a-secret-of-sixteen-chars', 'filter' => ['org.*', 'admin.drain_tested']], $owner))['data'];
        self::assertSame(['org.*', 'admin.drain_tested'], $drain['filter']);
        self::assertArrayNotHasKey('secret', $drain);
        $listed = $this->json($this->authedGet('/admin/organizations/' . $acme . '/drains', $admin))['data'];
        self::assertSame([$drain['id']], array_column($listed, 'id'));

        $tested = $this->json($this->authedPostJson('/admin/organizations/' . $acme . '/drains/' . $drain['id'] . '/test', [], $owner))['data'];
        self::assertSame($drain['id'], $tested['id']);
        self::assertNull($tested['last_delivery_at'], 'no HTTP client in the test wiring, so nothing was delivered');
        $recorded = $this->json($this->authedGet('/admin/audit?names=admin.drain_tested', $owner))['data'];
        self::assertSame([$acme], array_column($recorded, 'organization_id'));
        self::assertSame($drain['id'], $recorded[0]['data']['drain_id']);

        self::assertSame('deleted', $this->json($this->authedDelete('/admin/organizations/' . $acme . '/drains/' . $drain['id'], $owner))['data']['status']);
        $this->problem($this->authedDelete('/admin/organizations/' . $acme . '/drains/' . $drain['id'], $owner), 404, 'admin_not_found');
        self::assertSame([], $this->json($this->authedGet('/admin/organizations/' . $acme . '/drains', $owner))['data']);
    }
}

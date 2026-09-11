<?php

declare(strict_types=1);

namespace Polaris\Admin\Tests\Functional;

use DateTimeImmutable;
use Polaris\Admin\Principal\Role;

use function array_column;

final class AdminKeysGrantsAndStatsTest extends AdminTestCase
{
    public function testKeysAndGrantsAreOwnerOnlyAndAudited(): void
    {
        $ada = $this->login('ada@example.com');
        $adaId = $this->userId('ada@example.com');
        $owner = $this->operator();

        $this->problem($this->authedPostJson('/admin/keys', ['name' => '', 'role' => 'support'], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPostJson('/admin/keys', ['name' => 'CI', 'role' => 'root'], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPostJson('/admin/keys', ['name' => 'CI', 'role' => 'support', 'ip_allowlist' => ['nowhere']], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPostJson('/admin/keys', ['name' => 'CI', 'role' => 'support', 'expires_at' => 'soon'], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPostJson('/admin/keys', ['name' => 'CI', 'role' => 'support', 'scope' => 'no-such-org'], $owner), 422, 'admin_invalid_input');
        $created = $this->json($this->authedPostJson('/admin/keys', ['name' => 'CI', 'role' => 'support', 'ip_allowlist' => ['10.0.0.0/8'], 'expires_at' => '2030-01-01T00:00:00+00:00'], $owner))['data'];
        self::assertStringStartsWith('pak_', $created['key']);
        self::assertSame(['CI', 'support', 'instance', ['10.0.0.0/8'], '2030-01-01T00:00:00+00:00'], [$created['name'], $created['role'], $created['scope'], $created['ip_allowlist'], $created['expires_at']]);
        $this->problem($this->authedGet('/admin/users', $created['key']), 401, 'admin_unauthorized', 'the test client has no address, so the allowlist denies');

        $this->problem($this->authedGet('/admin/users', $ada), 401, 'admin_unauthorized');
        $this->problem($this->authedPostJson('/admin/grants', ['user_id' => $adaId, 'role' => 'boss'], $owner), 422, 'admin_invalid_input');
        $this->problem($this->authedPostJson('/admin/grants', ['user_id' => 'nobody', 'role' => 'support'], $owner), 404, 'admin_not_found');
        $grant = $this->json($this->authedPostJson('/admin/grants', ['user_id' => $adaId, 'role' => 'support'], $owner))['data'];
        self::assertSame([$adaId, 'support', 'instance'], [$grant['user_id'], $grant['role'], $grant['scope']]);
        self::assertCount(2, $this->json($this->authedGet('/admin/users', $ada))['data'], 'ada is an operator now');
        $this->problem($this->authedPostJson('/admin/users/' . $this->userId(self::OPERATOR) . '/ban', [], $ada), 403, 'admin_forbidden');
        $this->problem($this->authedGet('/admin/grants', $ada), 403, 'admin_forbidden');

        $replaced = $this->json($this->authedPostJson('/admin/grants', ['user_id' => $adaId, 'role' => 'viewer', 'expires_at' => '2020-01-01T00:00:00+00:00'], $owner))['data'];
        self::assertSame($grant['id'], $replaced['id'], 'one grant per user');
        $this->problem($this->authedGet('/admin/users', $ada), 401, 'admin_unauthorized', 'lapsed');

        $grants = $this->json($this->authedGet('/admin/grants', $owner))['data'];
        self::assertCount(2, $grants, 'the operator\'s own and ada\'s');
        self::assertSame('deleted', $this->json($this->authedDelete('/admin/grants/' . $grant['id'], $owner))['data']['status']);
        $this->problem($this->authedDelete('/admin/grants/' . $grant['id'], $owner), 404, 'admin_not_found');
        self::assertSame(['admin.grant_deleted', 'admin.grant_created', 'admin.grant_created', 'admin.key_created'], array_column($this->json($this->authedGet('/admin/audit?names=admin.key_created,admin.grant_created,admin.grant_deleted', $owner))['data'], 'name'));
    }

    public function testAnOrganizationOwnerCreatesKeysAndGrantsForTheirOrganizationOnly(): void
    {
        $ada = $this->login('ada@example.com');
        $adaId = $this->userId('ada@example.com');
        $acme = $this->createOrg('Acme Rockets', $ada);
        $globex = $this->createOrg('Globex', $ada);
        $orgOwner = $this->key(Role::Owner, $acme);

        $this->problem($this->authedPostJson('/admin/keys', ['name' => 'Wide', 'role' => 'viewer'], $orgOwner), 403, 'admin_forbidden');
        $this->problem($this->authedPostJson('/admin/keys', ['name' => 'Other', 'role' => 'viewer', 'scope' => $globex], $orgOwner), 403, 'admin_forbidden');
        $key = $this->json($this->authedPostJson('/admin/keys', ['name' => 'Acme', 'role' => 'viewer', 'scope' => $acme], $orgOwner))['data'];
        self::assertSame($acme, $key['scope']);
        $this->problem($this->authedPostJson('/admin/grants', ['user_id' => $adaId, 'role' => 'viewer'], $orgOwner), 403, 'admin_forbidden');
        self::assertSame($acme, $this->json($this->authedPostJson('/admin/grants', ['user_id' => $adaId, 'role' => 'viewer', 'scope' => $acme], $orgOwner))['data']['scope']);
        self::assertSame('Acme Rockets', $this->json($this->authedGet('/admin/organizations/' . $acme, $ada))['data']['name'], 'ada reads her organization as a scoped viewer');
        $this->problem($this->authedGet('/admin/keys', $orgOwner), 403, 'admin_forbidden', 'listing keys is instance-wide');
    }

    public function testStatsCountTheInstance(): void
    {
        $this->login('ada@example.com');
        $this->login('ada@example.com');
        $ada = $this->login('bob@example.com');
        $this->createOrg('Acme Rockets', $ada);
        $viewer = $this->key(Role::Viewer, expiresAt: new DateTimeImmutable('+1 hour'));

        $stats = $this->json($this->authedGet('/admin/stats', $viewer))['data'];
        self::assertSame(['users' => 2, 'organizations' => 1, 'active_sessions' => 3], $stats['totals']);
        self::assertSame(['24h' => 2, '7d' => 2, '30d' => 2], $stats['sign_ups']);
        self::assertSame(['24h' => 3, '7d' => 3, '30d' => 3], $stats['sign_ins']);
        self::assertSame(['24h' => 2, '7d' => 2, '30d' => 2], $stats['active_users']);
        $this->problem($this->get('/admin/stats'), 401, 'admin_unauthorized');
    }
}

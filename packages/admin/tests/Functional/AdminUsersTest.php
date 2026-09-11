<?php

declare(strict_types=1);

namespace Polaris\Admin\Tests\Functional;

use Polaris\Admin\AdminAudit;
use Polaris\Admin\Principal\Role;

use function array_column;
use function str_ends_with;

final class AdminUsersTest extends AdminTestCase
{
    public function testAnOwnerManagesUsersAndEveryActionIsAudited(): void
    {
        $ada = $this->login('ada@example.com');
        $adaId = $this->userId('ada@example.com');
        $owner = $this->operator();
        $ownerId = $this->userId(self::OPERATOR);

        $list = $this->json($this->authedGet('/admin/users', $owner));
        self::assertSame(['ada@example.com', self::OPERATOR], array_column($list['data'], 'email'), 'oldest first');
        self::assertNull($list['next_cursor']);
        $first = $this->json($this->authedGet('/admin/users?limit=1', $owner));
        self::assertSame($adaId, $first['next_cursor']);
        $second = $this->json($this->authedGet('/admin/users?limit=1&cursor=' . $first['next_cursor'], $owner));
        self::assertSame([self::OPERATOR], array_column($second['data'], 'email'));
        self::assertNull($second['next_cursor']);
        self::assertSame([$adaId], array_column($this->json($this->authedGet('/admin/users?email=ada%40example.com', $owner))['data'], 'id'));
        $this->problem($this->authedGet('/admin/users?status=banned', $owner), 422, 'admin_invalid_input');

        $read = $this->json($this->authedGet('/admin/users/' . $adaId, $owner))['data'];
        self::assertSame(['id' => $adaId, 'email' => 'ada@example.com', 'status' => 'active', 'email_verified' => true], ['id' => $read['id'], 'email' => $read['email'], 'status' => $read['status'], 'email_verified' => $read['email_verified']]);
        self::assertNotNull($read['last_active_at'], 'the audit activity tracker saw the sign-in');
        $this->problem($this->authedGet('/admin/users/nobody', $owner), 404, 'admin_not_found');

        self::assertSame('disabled', $this->json($this->authedPostJson('/admin/users/' . $adaId . '/ban', [], $owner))['data']['status']);
        self::assertSame('disabled', $this->json($this->authedGet('/admin/users/' . $adaId, $owner))['data']['status']);
        self::assertNotSame(200, $this->postJson('/auth/login', ['email' => 'ada@example.com', 'password' => self::PASSWORD])->getStatusCode(), 'a banned user cannot sign in');
        $this->problem($this->authedPostJson('/admin/users/' . $ownerId . '/ban', [], $owner), 409, 'admin_conflict');
        self::assertSame('active', $this->json($this->authedPostJson('/admin/users/' . $adaId . '/unban', [], $owner))['data']['status']);

        $weak = $this->problem($this->authedPostJson('/admin/users/' . $adaId . '/password', ['password' => 'short'], $owner), 422, 'admin_invalid_input');
        self::assertNotEmpty($weak['errors']);
        self::assertSame('password_set', $this->json($this->authedPostJson('/admin/users/' . $adaId . '/password', ['password' => 'a brand new passphrase'], $owner))['data']['status']);
        self::assertSame(200, $this->postJson('/auth/login', ['email' => 'ada@example.com', 'password' => 'a brand new passphrase'])->getStatusCode());
        self::assertNotSame(200, $this->postJson('/auth/login', ['email' => 'ada@example.com', 'password' => self::PASSWORD])->getStatusCode());

        $impersonation = $this->json($this->authedPostJson('/admin/users/' . $adaId . '/impersonate', [], $owner))['data'];
        self::assertSame('Bearer', $impersonation['token_type']);
        self::assertSame($ownerId, $impersonation['impersonated_by']);
        self::assertSame('ada@example.com', $this->json($this->authedGet('/auth/me', $impersonation['access_token']))['data']['email'], 'the token acts as the user');
        $this->problem($this->authedGet('/admin/users', $impersonation['access_token']), 403, 'admin_impersonation_denied');

        self::assertSame('deleted', $this->json($this->authedDelete('/admin/users/' . $adaId, $owner))['data']['status']);
        $deleted = $this->json($this->authedGet('/admin/users/' . $adaId, $owner))['data'];
        self::assertTrue(str_ends_with($deleted['email'], '@deleted.invalid'));
        self::assertSame('disabled', $deleted['status']);
        $this->problem($this->authedDelete('/admin/users/' . $ownerId, $owner), 409, 'admin_conflict');

        $trail = $this->json($this->authedGet('/admin/audit?subject_id=' . $adaId . '&names=admin.user_banned,admin.user_unbanned,admin.password_set,admin.user_impersonated,admin.user_deleted', $owner));
        self::assertSame([AdminAudit::USER_DELETED, AdminAudit::USER_IMPERSONATED, AdminAudit::PASSWORD_SET, AdminAudit::USER_UNBANNED, AdminAudit::USER_BANNED], array_column($trail['data'], 'name'));
        self::assertSame(['admin'], array_unique(array_column($trail['data'], 'actor_type')));
        self::assertSame([$ownerId], array_unique(array_column($trail['data'], 'actor_id')));
        self::assertSame(['actor_role' => 'owner', 'actor_scope' => 'instance'], $trail['data'][4]['data']);
        self::assertContains('user.disabled', array_column($this->json($this->authedGet('/admin/audit?actor_id=' . $ownerId, $owner))['data'], 'name'), 'the core event carries the operator as actor too');

        $this->problem($this->get('/admin/users'), 401, 'admin_unauthorized');
        $this->problem($this->authedGet('/admin/users', $ada), 401, 'admin_unauthorized');
    }

    public function testASuperadminIsAnOwnerWithoutAGrantAndCannotBeImpersonated(): void
    {
        $root = $this->login('root@example.com');
        $rootId = $this->userId('root@example.com');
        $this->problem($this->authedGet('/admin/keys', $root), 401, 'admin_unauthorized');
        $this->createOrg('Root', $root);
        $membership = $this->adapter->findOne('auth_memberships', ['user_id' => $rootId]);
        $role = $this->adapter->findOne('auth_roles', ['slug' => 'superadmin', 'organization_id' => null]);
        $this->adapter->insert('auth_membership_roles', ['membership_id' => $membership['id'] ?? '', 'role_id' => $role['id'] ?? '']);

        self::assertSame([], $this->json($this->authedGet('/admin/keys', $root))['data'], 'owner-only route');

        $owner = $this->operator();
        $this->problem($this->authedPostJson('/admin/users/' . $rootId . '/impersonate', [], $owner), 403, 'admin_impersonation_denied');
    }

    public function testAViewerKeyReadsAndCannotMutateAndADeletedKeyIsRefused(): void
    {
        $this->login('ada@example.com');
        $adaId = $this->userId('ada@example.com');
        $viewer = $this->key(Role::Viewer);
        $support = $this->key(Role::Support);

        self::assertCount(1, $this->json($this->authedGet('/admin/users', $viewer))['data']);
        $this->problem($this->authedPostJson('/admin/users/' . $adaId . '/ban', [], $viewer), 403, 'admin_forbidden');
        $this->problem($this->authedPostJson('/admin/users/' . $adaId . '/ban', [], $support), 403, 'admin_forbidden');
        $this->problem($this->authedPostJson('/admin/users/' . $adaId . '/impersonate', [], $support), 403, 'admin_forbidden');
        $this->problem($this->authedGet('/admin/keys', $support), 403, 'admin_forbidden');

        $owner = $this->operator();
        $keys = $this->json($this->authedGet('/admin/keys', $owner))['data'];
        self::assertCount(2, $keys);
        self::assertArrayNotHasKey('key', $keys[0]);
        self::assertSame('deleted', $this->json($this->authedDelete('/admin/keys/' . $keys[0]['id'], $owner))['data']['status']);
        $this->problem($this->authedGet('/admin/users', $viewer), 401, 'admin_unauthorized');
        $this->problem($this->authedGet('/admin/users', 'pak_not-a-key'), 401, 'admin_unauthorized');
    }
}

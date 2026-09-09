<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Polaris\Event\OrganizationCreated;
use Polaris\Event\UserRegistered;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\TokenService;

use function array_key_last;
use function is_string;

/**
 * Drives the #31 `/orgs` endpoints end to end: creating an organization makes the verified caller
 * its owner (with the system role templates cloned per-org), slugs are unique and auto-derived, the
 * create is all-or-nothing, and the list returns only the caller's organizations.
 */
final class OrganizationEndpointsTest extends FunctionalTestCase
{
    private const string EMAIL = 'founder@example.com';
    private const string PASSWORD = 'Sup3r-Secret-Passw0rd';

    public function testCreateMakesTheCallerTheOwnerWithClonedRoles(): void
    {
        $access = $this->registerVerifyLogin(self::EMAIL);
        $userId = $this->userId(self::EMAIL);

        $response = $this->authedPostJson('/orgs', ['name' => 'Acme Inc'], $access);
        self::assertSame(201, $response->getStatusCode());

        $data = $this->json($response)['data'] ?? [];
        self::assertSame('Acme Inc', $data['name'] ?? null);
        self::assertSame('acme-inc', $data['slug'] ?? null, 'slug is auto-derived from the name');
        self::assertSame('owner', $data['role'] ?? null);
        $orgId = is_string($data['id'] ?? null) ? $data['id'] : '';
        self::assertNotSame('', $orgId);

        $database = $this->adapter;

        // The org is persisted with the caller as creator.
        self::assertSame(1, $database->count('auth_organizations', ['id' => $orgId, 'created_by' => $userId, 'status' => 'active']));

        // owner/admin/member templates are cloned into org-scoped, tenant-editable roles (not superadmin).
        self::assertSame(3, $database->count('auth_roles', ['organization_id' => $orgId, 'is_system' => false]));
        $ownerRoleId = $this->roleId($orgId, 'owner');
        self::assertNotSame('', $ownerRoleId);
        self::assertSame(0, $database->count('auth_roles', ['organization_id' => $orgId, 'slug' => 'superadmin']));

        // The cloned owner role carries all 10 org permissions.
        self::assertSame(10, $database->count('auth_role_permissions', ['role_id' => $ownerRoleId]));

        // The caller has an active owner membership.
        $membershipId = $this->activeMembershipId($orgId, $userId);
        self::assertNotSame('', $membershipId);
        self::assertSame(1, $database->count('auth_membership_roles', ['membership_id' => $membershipId, 'role_id' => $ownerRoleId]));

        // org.created is emitted.
        $events = $this->events->ofType(OrganizationCreated::class);
        self::assertCount(1, $events);
        self::assertSame($orgId, $events[0]->organizationId);
        self::assertSame($userId, $events[0]->ownerUserId);
    }

    public function testSlugMustBeUnique(): void
    {
        $access = $this->registerVerifyLogin(self::EMAIL);

        self::assertSame(201, $this->authedPostJson('/orgs', ['name' => 'Acme'], $access)->getStatusCode());

        $conflict = $this->authedPostJson('/orgs', ['name' => 'Another', 'slug' => 'acme'], $access);
        self::assertSame(409, $conflict->getStatusCode());
        self::assertSame('conflict', $this->json($conflict)['error'] ?? null);
    }

    public function testCreateFailsClosedOnConflictLeavingNoPartialState(): void
    {
        $access = $this->registerVerifyLogin(self::EMAIL);
        self::assertSame(201, $this->authedPostJson('/orgs', ['name' => 'Acme'], $access)->getStatusCode());

        $rolesBefore = $this->adapter->count('auth_roles', []);
        $membershipsBefore = $this->adapter->count('auth_memberships', []);

        self::assertSame(409, $this->authedPostJson('/orgs', ['name' => 'Acme'], $access)->getStatusCode());

        self::assertSame($rolesBefore, $this->adapter->count('auth_roles', []));
        self::assertSame($membershipsBefore, $this->adapter->count('auth_memberships', []));
        self::assertSame(1, $this->adapter->count('auth_organizations', []));
    }

    public function testNameIsRequiredAndUnderivableSlugIsRejected(): void
    {
        $access = $this->registerVerifyLogin(self::EMAIL);

        self::assertSame(422, $this->authedPostJson('/orgs', ['name' => '  '], $access)->getStatusCode());
        self::assertSame(422, $this->authedPostJson('/orgs', ['name' => '###'], $access)->getStatusCode());
        self::assertSame(422, $this->authedPostJson('/orgs', ['name' => 'Acme', 'slug' => 'Not Valid'], $access)->getStatusCode());
    }

    public function testCreateRequiresAuthentication(): void
    {
        self::assertSame(401, $this->postJson('/orgs', ['name' => 'Acme'])->getStatusCode());
    }

    public function testCreateRequiresAVerifiedEmail(): void
    {
        // A real (registered but unverified) user, with a token whose email_verified claim is false —
        // minted directly, bypassing the verified-email gate that login itself enforces.
        $this->postJson('/auth/register', ['email' => 'unverified@example.com', 'password' => self::PASSWORD]);
        $this->unitOfWork->clear();
        $userId = $this->userId('unverified@example.com');

        $tokens = $this->graph->tokens();
        self::assertInstanceOf(TokenService::class, $tokens);
        $principal = new SessionPrincipal(userId: $userId, emailVerified: false);
        $access = $tokens->issue($principal, ClientContext::none())->accessToken;

        $response = $this->authedPostJson('/orgs', ['name' => 'Acme'], $access);
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('email_unverified', $this->json($response)['error'] ?? null);
    }

    public function testListReturnsOnlyTheCallersOrganizations(): void
    {
        $access = $this->registerVerifyLogin(self::EMAIL);
        $this->authedPostJson('/orgs', ['name' => 'Acme'], $access);
        $this->authedPostJson('/orgs', ['name' => 'Globex'], $access);

        $list = $this->json($this->authedGet('/orgs', $access))['data'] ?? [];
        self::assertCount(2, $list);
        $slugs = [];
        foreach ($list as $org) {
            $slugs[] = $org['slug'] ?? null;
        }
        self::assertContains('acme', $slugs);
        self::assertContains('globex', $slugs);

        // A different user sees none of them.
        $other = $this->registerVerifyLogin('other@example.com');
        self::assertCount(0, $this->json($this->authedGet('/orgs', $other))['data'] ?? []);
    }

    public function testListRequiresAuthentication(): void
    {
        self::assertSame(401, $this->get('/orgs')->getStatusCode());
    }

    private function registerVerifyLogin(string $email): string
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        $registered = $this->events->ofType(UserRegistered::class);
        $token = $registered[array_key_last($registered)]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();

        $body = $this->json($this->postJson('/auth/login', ['email' => $email, 'password' => self::PASSWORD]));

        return (string) ($body['data']['access_token'] ?? '');
    }

    private function userId(string $email): string
    {
        return $this->firstId($this->adapter->findMany('auth_users', ['email' => $email]));
    }

    private function roleId(string $organizationId, string $slug): string
    {
        return $this->firstId($this->adapter->findMany('auth_roles', ['organization_id' => $organizationId, 'slug' => $slug]));
    }

    private function activeMembershipId(string $organizationId, string $userId): string
    {
        return $this->firstId($this->adapter->findMany('auth_memberships', ['organization_id' => $organizationId, 'user_id' => $userId, 'status' => 'active']));
    }

    /**
     * @param array<int, mixed> $rows
     */
    private function firstId(array $rows): string
    {
        foreach ($rows as $row) {
            if (is_string($row['id'] ?? null)) {
                return $row['id'];
            }
        }

        return '';
    }
}

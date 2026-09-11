<?php

declare(strict_types=1);

namespace Polaris\Admin\Tests\Functional;

use DateTimeImmutable;
use Override;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Grants;
use Polaris\Admin\Keys;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Audit\AuditPlugin;
use Polaris\Event\UserRegistered;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\Uid\Uuid;

use function array_key_last;
use function dirname;
use function preg_replace;

/**
 * The admin routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with the
 * audit plugin under them; the recorded steps in tests/Contract/fixtures replay identically.
 */
abstract class AdminTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';
    protected const string OPERATOR = 'operator@example.com';

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new AdminPlugin()];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    /**
     * Registers (once), verifies and logs the user in; their access token.
     */
    protected function login(string $email): string
    {
        $register = $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        if ($register->getStatusCode() < 300) {
            $registered = $this->events->ofType(UserRegistered::class);
            $this->postJson('/auth/email/verify', ['token' => $registered[array_key_last($registered)]->verificationToken]);
            $this->unitOfWork->clear();
        }

        return (string) ($this->json($this->postJson('/auth/login', ['email' => $email, 'password' => self::PASSWORD]))['data']['access_token'] ?? '');
    }

    /**
     * The operator's access token, with an instance-wide grant of `$role` (an owner by default).
     */
    protected function operator(Role $role = Role::Owner, string $scope = Principal::SCOPE_INSTANCE): string
    {
        $access = $this->login(self::OPERATOR);
        $this->graph->get(Grants::class)->grant($this->userId(self::OPERATOR), $role, $scope);

        return $access;
    }

    /**
     * @param list<string> $allowlist
     */
    protected function key(Role $role, string $scope = Principal::SCOPE_INSTANCE, array $allowlist = [], ?DateTimeImmutable $expiresAt = null): string
    {
        return $this->graph->get(Keys::class)->create('test', $role, $scope, $allowlist, $expiresAt, 'test')->plaintext;
    }

    protected function userId(string $email): string
    {
        $row = $this->adapter->findOne('auth_users', ['email' => $email]);
        $id = $row['id'] ?? null;
        self::assertIsString($id, "No user $email.");

        return $id;
    }

    protected function createOrg(string $name, string $access): string
    {
        return (string) ($this->json($this->authedPostJson('/orgs', ['name' => $name], $access))['data']['id'] ?? '');
    }

    /**
     * Makes the user an active member of the organization with the given role slug, without the
     * invitation round trip.
     */
    protected function join(string $email, string $organizationId, string $roleSlug): void
    {
        $role = $this->adapter->findOne('auth_roles', ['organization_id' => $organizationId, 'slug' => $roleSlug]);
        self::assertIsString($role['id'] ?? null, "No $roleSlug role in the organization.");
        $now = new DateTimeImmutable();
        $membershipId = Uuid::v7()->toRfc4122();
        $this->adapter->insert('auth_memberships', [
            'id' => $membershipId,
            'user_id' => $this->userId($email),
            'organization_id' => $organizationId,
            'status' => 'active',
            'invited_by' => null,
            'joined_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $this->adapter->insert('auth_membership_roles', ['membership_id' => $membershipId, 'role_id' => $role['id']]);
    }

    /**
     * @return array<string, mixed>
     */
    protected function problem(ResponseInterface $response, int $status, string $error, string $message = ''): array
    {
        self::assertSame($status, $response->getStatusCode(), $message);
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        $body = $this->json($response);
        self::assertSame($error, $body['error']);
        self::assertSame('https://polaris.univeros.io/problems/' . preg_replace('/_/', '/', $error, 1), $body['type'], 'the type URL matches the error code');

        return $body;
    }
}

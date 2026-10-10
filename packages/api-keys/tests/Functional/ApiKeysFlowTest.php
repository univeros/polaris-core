<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Tests\Functional;

use DateTimeImmutable;
use Laminas\Diactoros\ServerRequestFactory;
use Polaris\ApiKeys\AuditNames;
use Polaris\ApiKeys\Event\ApiKeyEvent;
use Polaris\ApiKeys\Keys;
use Polaris\ApiKeys\Model\ApiKey;
use Polaris\ApiKeys\Schema;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Psr\Http\Message\ServerRequestInterface;

use function ksort;
use function substr;

/**
 * WP3 acceptance 1: an API key resolves a principal on every Polaris route, core's and a plugin's, with
 * the key's permissions intersected with the owner's; its rate limit and expiry are enforced; a
 * rotation keeps the old key for the grace window; the secret is shown once.
 */
final class ApiKeysFlowTest extends ApiKeysTestCase
{
    public function testAKeyActsAsItsOwnerWithTheDelegatedPermissionsOnEveryRoute(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');

        // Create: the secret is in this response only; the list and the read never show it.
        $created = $this->authedPostJson('/api-keys', ['name' => 'CI deploy', 'permissions' => ['org.read'], 'metadata' => ['pipeline' => 'main']], $session);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $key = $this->json($created)['data'];
        $secret = (string) $key['key'];
        self::assertStringStartsWith('pk_live_', $secret);
        self::assertSame(['org.read'], $key['permissions']);
        self::assertSame($orgId, $key['organization_id'], 'the key acts in the active organization');
        self::assertSame(ApiKey::OWNER_USER, $key['owner_type']);
        $listed = $this->json($this->authedGet('/api-keys', $session))['data'];
        self::assertCount(1, $listed);
        self::assertArrayNotHasKey('key', $listed[0]);
        self::assertSame(substr($secret, -4), $listed[0]['hint']);
        self::assertArrayNotHasKey('key', $this->json($this->authedGet('/api-keys/' . $key['id'], $session))['data']);

        // A core route and a plugin route accept the key as the owner, as Bearer and as x-api-key.
        $me = $this->authedGet('/auth/me', $secret);
        self::assertSame(200, $me->getStatusCode(), (string) $me->getBody());
        self::assertSame($userId, $this->json($me)['data']['id']);
        self::assertSame(200, $this->handle($this->request('GET', '/audit/me')->withHeader('x-api-key', $secret))->getStatusCode(), 'a plugin route, through the x-api-key header');
        // The owner holds org.read and members.read (owner role); the key was delegated org.read only.
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId, $secret)->getStatusCode());
        self::assertSame(403, $this->authedGet('/orgs/' . $orgId . '/members', $secret)->getStatusCode(), 'held by the owner, not delegated');
        // A step-up route is never reachable with a key.
        $this->problem($this->authedPostJson('/auth/mfa/recovery-codes/regenerate', [], $secret), 403, 'api_keys_not_allowed');

        // Permissions are bounded by the owner's: an unknown one and one the owner lacks are refused.
        $this->problem($this->authedPostJson('/api-keys', ['name' => 'x', 'permissions' => ['users.manage']], $session), 403, 'api_keys_permission_not_held');
        $this->problem($this->authedPostJson('/api-keys', ['name' => 'x', 'permissions' => ['nothing.here']], $session), 422, 'api_keys_invalid_input');
        // A key cannot delegate more than it holds either.
        $this->problem($this->authedPostJson('/api-keys', ['name' => 'from a key', 'permissions' => ['members.read']], $secret), 403, 'api_keys_permission_not_held');

        // Verify, for an app that proxies.
        $verified = $this->json($this->authedPostJson('/api-keys/verify', ['key' => $secret], $session))['data'];
        self::assertTrue($verified['valid']);
        self::assertSame([$key['id'], $userId, ['org.read']], [$verified['id'], $verified['subject'], $verified['permissions']]);
        self::assertFalse($this->json($this->authedPostJson('/api-keys/verify', ['key' => 'pk_live_nothing'], $session))['data']['valid']);

        // Update: the name and the permissions (still bounded); clearing the limit.
        $updated = $this->json($this->authedPatch('/api-keys/' . $key['id'], ['name' => 'CI deploy (renamed)', 'permissions' => ['org.read', 'members.read'], 'rate_limit' => ['window' => 60, 'max' => 2]], $session))['data'];
        self::assertSame(['org.read', 'members.read'], $updated['permissions']);
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId . '/members', $secret)->getStatusCode(), 'members.read delegated now');

        // The key's own rate limit: two a minute (the members call was the first), the third is 429 with the headers.
        $second = $this->authedGet('/auth/me', $secret);
        self::assertSame(['200', '0'], [(string) $second->getStatusCode(), $second->getHeaderLine('X-RateLimit-Remaining')]);
        $third = $this->authedGet('/auth/me', $secret);
        self::assertSame(429, $third->getStatusCode());
        self::assertSame('0', $third->getHeaderLine('X-RateLimit-Remaining'));
        self::assertNotSame('', $third->getHeaderLine('Retry-After'));

        // Rotate: a new secret; the old one still answers (within the grace), the successor too.
        $this->authedPatch('/api-keys/' . $key['id'], ['rate_limit' => null], $session);
        $rotated = $this->authedPostJson('/api-keys/' . $key['id'] . '/rotate', [], $session);
        self::assertSame(201, $rotated->getStatusCode(), (string) $rotated->getBody());
        $successor = $this->json($rotated)['data'];
        self::assertNotSame($secret, $successor['key']);
        self::assertSame($key['id'], $successor['rotated_from']);
        self::assertSame(200, $this->authedGet('/auth/me', $secret)->getStatusCode(), 'the old key answers during the grace');
        self::assertSame(200, $this->authedGet('/auth/me', (string) $successor['key'])->getStatusCode());
        self::assertSame(ApiKey::STATUS_ROTATED, $this->json($this->authedGet('/api-keys/' . $key['id'], $session))['data']['status']);
        $this->problem($this->authedPostJson('/api-keys/' . $key['id'] . '/rotate', [], $session), 403, 'api_keys_forbidden', 'rotate the successor instead');

        // Revoke: the key stops at once; it is gone from the list; the successor lives.
        self::assertSame('revoked', $this->json($this->authedDelete('/api-keys/' . $key['id'], $session))['data']['status']);
        self::assertSame(401, $this->authedGet('/auth/me', $secret)->getStatusCode());
        self::assertSame(200, $this->authedGet('/auth/me', (string) $successor['key'])->getStatusCode());
        self::assertSame(404, $this->authedGet('/api-keys/' . $key['id'], $session)->getStatusCode());
        self::assertCount(1, $this->json($this->authedGet('/api-keys', $session))['data']);

        // Audited, every one of them.
        $names = [];
        foreach ($this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::CREATED, AuditNames::UPDATED, AuditNames::ROTATED, AuditNames::REVOKED]))->events as $event) {
            $names[$event->name] = ($names[$event->name] ?? 0) + 1;
        }
        ksort($names);
        self::assertSame([AuditNames::CREATED => 1, AuditNames::REVOKED => 1, AuditNames::ROTATED => 1, AuditNames::UPDATED => 2], $names);
        self::assertCount(5, $this->events->ofType(ApiKeyEvent::class));
    }

    public function testAnOrganizationsKeyIsManagedByItsAdminsAndActsAsItsCreator(): void
    {
        [$adaId, $ada] = $this->login('ada@example.com');
        [$orgId, $ada] = $this->organization($ada, 'Acme');
        [, $bob] = $this->login('bob@example.com');

        // Bob is nobody in Acme: he cannot create its keys. Ada, its owner, can.
        $this->problem($this->authedPostJson('/api-keys', ['name' => 'Acme bot', 'organization_id' => $orgId], $bob), 403, 'api_keys_forbidden');
        $created = $this->authedPostJson('/api-keys', ['name' => 'Acme bot', 'organization_id' => $orgId, 'permissions' => ['members.read'], 'environment' => 'test'], $ada);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $key = $this->json($created)['data'];
        self::assertStringStartsWith('pk_test_', (string) $key['key']);
        self::assertSame([ApiKey::OWNER_ORGANIZATION, $orgId, $adaId], [$key['owner_type'], $key['owner_id'], $key['created_by']]);

        // The key lists under the organization, not under Ada; it acts as Ada in Acme with members.read only.
        self::assertCount(0, $this->json($this->authedGet('/api-keys', $ada))['data']);
        self::assertCount(1, $this->json($this->authedGet('/api-keys?organization_id=' . $orgId, $ada))['data']);
        $this->problem($this->authedGet('/api-keys?organization_id=' . $orgId, $bob), 403, 'api_keys_forbidden');
        $members = $this->authedGet('/orgs/' . $orgId . '/members', (string) $key['key']);
        self::assertSame(200, $members->getStatusCode(), (string) $members->getBody());
        self::assertSame(403, $this->authedGet('/orgs/' . $orgId, (string) $key['key'])->getStatusCode(), 'org.read was not delegated');
        self::assertSame($adaId, $this->json($this->authedGet('/auth/me', (string) $key['key']))['data']['id']);

        // Bob cannot see or revoke it; Ada can.
        self::assertSame(404, $this->authedGet('/api-keys/' . $key['id'], $bob)->getStatusCode());
        self::assertSame(404, $this->authedDelete('/api-keys/' . $key['id'], $bob)->getStatusCode());
        self::assertSame(200, $this->authedDelete('/api-keys/' . $key['id'], $ada)->getStatusCode());
        self::assertSame(401, $this->authedGet('/auth/me', (string) $key['key'])->getStatusCode());
    }

    public function testAnExpiredKeyAndATooLargeBudgetAreRefused(): void
    {
        [, $session] = $this->login('ada@example.com');
        $this->problem($this->authedPostJson('/api-keys', ['name' => 'old', 'expires_at' => '2020-01-01T00:00:00+00:00'], $session), 422, 'api_keys_invalid_input');
        $this->problem($this->authedPostJson('/api-keys', ['name' => 'old', 'rate_limit' => ['window' => 0, 'max' => 1]], $session), 422, 'api_keys_invalid_input');
        $this->problem($this->authedPostJson('/api-keys', ['name' => '', 'permissions' => []], $session), 422, 'api_keys_invalid_input');
        $created = $this->json($this->authedPostJson('/api-keys', ['name' => 'short-lived', 'expires_at' => '2099-01-01T00:00:00+00:00'], $session))['data'];
        self::assertSame('2099-01-01T00:00:00+00:00', $created['expires_at']);
        self::assertSame(200, $this->authedGet('/auth/me', (string) $created['key'])->getStatusCode());
        // Expiry is enforced at authentication: the service answers null once the clock passes it (unit-tested with a mutable clock); here the row is expired by hand.
        $this->graph->database()->update(Schema::KEYS, ['id' => $created['id']], ['expires_at' => new DateTimeImmutable('2020-01-01T00:00:00+00:00')]);
        self::assertSame(401, $this->authedGet('/auth/me', (string) $created['key'])->getStatusCode());
        self::assertNull($this->graph->get(Keys::class)->authenticate((string) $created['key']));
        self::assertSame(ApiKey::STATUS_EXPIRED, $this->json($this->authedGet('/api-keys/' . $created['id'], $session))['data']['status']);
    }

    private function request(string $method, string $path): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest($method, $path);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Scim\Tests\Functional;

use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Scim\Patch;

use function array_column;

/**
 * A directory provisions users and groups over the SCIM routes.
 */
final class ScimProvisioningTest extends ScimTestCase
{
    public function testADirectoryProvisionsUsersAndGroups(): void
    {
        $ada = $this->login('ada@acme.example');
        [$acme, $owner] = $this->organization('Acme Rockets', $ada);
        [$connection, $token] = $this->connection($acme, $owner);
        [$other, $otherToken] = $this->connection($acme, $owner, 'Entra');
        $base = '/scim/v2/' . $connection;

        $this->scimError($this->scim('GET', $base . '/Users'), 401);
        $this->scimError($this->scim('GET', $base . '/Users', [], 'pst_nope'), 401);
        $this->scimError($this->scim('GET', $base . '/Users', [], $otherToken), 401, null);
        self::assertSame('application/scim+json', $this->scim('GET', $base . '/ServiceProviderConfig', [], $token)->getHeaderLine('Content-Type'));
        self::assertSame(2, $this->json($this->scim('GET', $base . '/Schemas', [], $token))['totalResults']);
        self::assertSame(['User', 'Group'], array_column($this->json($this->scim('GET', $base . '/ResourceTypes', [], $token))['Resources'], 'id'));

        $this->scimError($this->scim('POST', $base . '/Users', ['userName' => 'not an email'], $token), 400, 'invalidValue');
        $bob = $this->json($this->scim('POST', $base . '/Users', ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'], 'userName' => 'Bob@Acme.example', 'externalId' => 'okta-bob', 'name' => ['givenName' => 'Bob', 'familyName' => 'Builder'], 'emails' => [['value' => 'bob@acme.example', 'primary' => true]], 'active' => true], $token));
        self::assertSame(['bob@acme.example', 'Bob Builder', 'okta-bob', true, ['Member']], [$bob['userName'], $bob['displayName'], $bob['externalId'], $bob['active'], array_column($bob['groups'], 'display')]);
        self::assertSame(self::BASE . '/scim/v2/' . $connection . '/Users/' . $bob['id'], $bob['meta']['location']);
        $this->scimError($this->scim('POST', $base . '/Users', ['userName' => 'bob@acme.example'], $token), 409, 'uniqueness');
        $this->scimError($this->scim('GET', $base . '/Users?filter=userName%20pr', [], $token), 400, 'invalidFilter');
        $found = $this->json($this->scim('GET', $base . '/Users?filter=' . rawurlencode('userName eq "bob@acme.example"'), [], $token));
        self::assertSame([1, 1, [$bob['id']]], [$found['totalResults'], $found['itemsPerPage'], array_column($found['Resources'], 'id')]);
        self::assertSame(2, $this->json($this->scim('GET', $base . '/Users', [], $token))['totalResults'], 'ada and bob');
        self::assertSame(1, $this->json($this->scim('GET', $base . '/Users?startIndex=2&count=1', [], $token))['itemsPerPage']);
        self::assertSame($bob['id'], $this->json($this->scim('GET', $base . '/Users/' . $bob['id'], [], $token))['id']);
        $this->scimError($this->scim('GET', $base . '/Users/nope', [], $token), 404);

        $patched = $this->json($this->scim('PATCH', $base . '/Users/' . $bob['id'], ['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false], ['op' => 'replace', 'value' => ['displayName' => 'Robert']]]], $token));
        self::assertSame([false, 'Robert'], [$patched['active'], $patched['displayName']]);
        $this->scimError($this->scim('PATCH', $base . '/Users/' . $bob['id'], ['Operations' => []], $token), 400, 'invalidSyntax');
        $replaced = $this->json($this->scim('PUT', $base . '/Users/' . $bob['id'], ['userName' => 'bob@acme.example', 'displayName' => 'Bob', 'active' => true, 'externalId' => 'okta-bob-2'], $token));
        self::assertSame([true, 'Bob', 'okta-bob-2'], [$replaced['active'], $replaced['displayName'], $replaced['externalId']]);

        $group = $this->json($this->scim('POST', $base . '/Groups', ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'], 'displayName' => 'Engineering', 'externalId' => 'okta-eng', 'members' => [['value' => $bob['id']]]], $token));
        self::assertSame(['Engineering', 'okta-eng', [$bob['id']]], [$group['displayName'], $group['externalId'], array_column($group['members'], 'value')]);
        self::assertContains('Engineering', array_column($this->json($this->scim('GET', $base . '/Users/' . $bob['id'], [], $token))['groups'], 'display'));
        $this->scimError($this->scim('POST', $base . '/Groups', ['displayName' => 'Engineering'], $token), 409, 'uniqueness');
        self::assertSame(1, $this->json($this->scim('GET', $base . '/Groups?filter=' . rawurlencode('displayName eq "Engineering"'), [], $token))['totalResults']);
        self::assertSame(4, $this->json($this->scim('GET', $base . '/Groups', [], $token))['totalResults'], 'owner, admin, member and engineering');
        $adaId = $this->json($this->scim('GET', $base . '/Users?filter=' . rawurlencode('userName eq "ada@acme.example"'), [], $token))['Resources'][0]['id'];
        $patchedGroup = $this->json($this->scim('PATCH', $base . '/Groups/' . $group['id'], ['schemas' => [Patch::SCHEMA], 'Operations' => [['op' => 'add', 'path' => 'members', 'value' => [['value' => $adaId]]], ['op' => 'remove', 'path' => 'members[value eq "' . $bob['id'] . '"]']]], $token));
        self::assertSame([$adaId], array_column($patchedGroup['members'], 'value'));
        $replacedGroup = $this->json($this->scim('PUT', $base . '/Groups/' . $group['id'], ['displayName' => 'Platform', 'members' => [['value' => $bob['id']]]], $token));
        self::assertSame(['Platform', [$bob['id']]], [$replacedGroup['displayName'], array_column($replacedGroup['members'], 'value')]);
        $memberRole = $this->json($this->scim('GET', $base . '/Groups?filter=' . rawurlencode('displayName eq "Member"'), [], $token))['Resources'][0];
        $this->scimError($this->scim('PUT', $base . '/Groups/' . $memberRole['id'], ['displayName' => 'Renamed'], $token), 403, 'mutability');
        $this->scimError($this->scim('DELETE', $base . '/Groups/' . $memberRole['id'], [], $token), 403, 'mutability');
        self::assertSame(204, $this->scim('DELETE', $base . '/Groups/' . $group['id'], [], $token)->getStatusCode());
        $this->scimError($this->scim('GET', $base . '/Groups/' . $group['id'], [], $token), 404);

        self::assertSame(204, $this->scim('DELETE', $base . '/Users/' . $bob['id'], [], $token)->getStatusCode());
        $this->scimError($this->scim('GET', $base . '/Users/' . $bob['id'], [], $token), 404, null);
        self::assertSame(401, $this->postJson('/auth/login', ['email' => 'bob@acme.example', 'password' => self::PASSWORD])->getStatusCode(), 'deactivated');
        self::assertSame(1, $this->json($this->scim('GET', $base . '/Users', [], $token))['totalResults'], 'ada stays: her membership predates the connection');
        $state = $this->json($this->authedGet('/orgs/' . $acme . '/scim/connections/' . $connection, $owner))['data'];
        self::assertSame(['users' => 0, 'groups' => 0, 'provisioned_members' => 0], $state['sync']);
        self::assertNotNull($state['last_sync_at']);
        $names = array_column($this->graph->get(Store::class)->read(new AuditQuery(names: ['scim.user_created', 'scim.user_updated', 'scim.user_deactivated', 'scim.user_reactivated', 'scim.group_created', 'scim.group_updated', 'scim.group_deleted', 'scim.request_rejected']))->toArray()['data'], 'name');
        self::assertSame(['scim.user_deactivated', 'scim.group_deleted', 'scim.request_rejected', 'scim.request_rejected', 'scim.group_updated', 'scim.group_updated', 'scim.request_rejected', 'scim.group_created', 'scim.user_reactivated', 'scim.request_rejected', 'scim.user_deactivated', 'scim.request_rejected', 'scim.request_rejected', 'scim.user_created', 'scim.request_rejected'], $names);
        self::assertNotSame('', $other);
    }
}

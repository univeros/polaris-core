<?php

declare(strict_types=1);

namespace Polaris\Scim\Tests\Functional;

use Polaris\Admin\Principal\Role;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;

use function array_column;

/**
 * An organization manages its connections; the operators see every organization's.
 */
final class ScimConnectionsTest extends ScimTestCase
{
    public function testAnOrganizationCreatesRotatesAndDecommissionsItsConnections(): void
    {
        $ada = $this->login('ada@acme.example');
        [$acme, $owner] = $this->organization('Acme Rockets', $ada);
        $bob = $this->login('bob@example.com');

        self::assertSame(403, $this->authedGet('/orgs/' . $acme . '/scim/connections', $bob)->getStatusCode(), 'core gates the route on org.update');
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/scim/connections', ['name' => ''], $owner), 422, 'scim_invalid_input');
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/scim/connections', ['name' => 'Okta', 'deprovision' => 'purge'], $owner), 422, 'scim_invalid_input');
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/scim/connections', ['name' => 'Okta', 'sso_provider_id' => 'nope'], $owner), 422, 'scim_invalid_input');
        $created = $this->json($this->authedPostJson('/orgs/' . $acme . '/scim/connections', ['name' => 'Okta', 'deprovision' => 'delete'], $owner))['data'];
        self::assertStringStartsWith('pst_', $created['token']);
        self::assertSame(['Okta', 'active', 'delete', self::BASE . '/scim/v2/' . $created['id'], ['users' => 0, 'groups' => 0, 'provisioned_members' => 0]], [$created['name'], $created['status'], $created['deprovision'], $created['scim_base_url'], $created['sync']]);
        $listed = $this->json($this->authedGet('/orgs/' . $acme . '/scim/connections', $owner))['data'];
        self::assertSame([$created['id']], array_column($listed, 'id'));
        self::assertArrayNotHasKey('token', $listed[0]);
        $read = $this->json($this->authedGet('/orgs/' . $acme . '/scim/connections/' . $created['id'], $owner))['data'];
        self::assertSame($created['scim_base_url'], $read['scim_base_url']);
        $this->problem($this->authedGet('/orgs/' . $acme . '/scim/connections/nope', $owner), 404, 'scim_not_found');

        self::assertSame(200, $this->scim('GET', '/scim/v2/' . $created['id'] . '/ServiceProviderConfig', [], $created['token'])->getStatusCode());
        $rotated = $this->json($this->authedPostJson('/orgs/' . $acme . '/scim/connections/' . $created['id'] . '/rotate', [], $owner))['data'];
        self::assertStringStartsWith('pst_', $rotated['token']);
        $this->scimError($this->scim('GET', '/scim/v2/' . $created['id'] . '/ServiceProviderConfig', [], $created['token']), 401);
        self::assertSame(200, $this->scim('GET', '/scim/v2/' . $created['id'] . '/ServiceProviderConfig', [], $rotated['token'])->getStatusCode());

        $decommissioned = $this->json($this->authedDelete('/orgs/' . $acme . '/scim/connections/' . $created['id'], $owner))['data'];
        self::assertSame('decommissioned', $decommissioned['status']);
        self::assertNotNull($decommissioned['decommissioned_at']);
        $this->scimError($this->scim('GET', '/scim/v2/' . $created['id'] . '/ServiceProviderConfig', [], $rotated['token']), 401, null);
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/scim/connections/' . $created['id'] . '/rotate', [], $owner), 409, 'scim_conflict');
        self::assertSame('decommissioned', $this->json($this->authedDelete('/orgs/' . $acme . '/scim/connections/' . $created['id'], $owner))['data']['status'], 'idempotent');
        self::assertSame(['scim.connection_decommissioned', 'scim.connection_rotated', 'scim.connection_created'], array_column($this->graph->get(Store::class)->read(new AuditQuery(names: ['scim.connection_created', 'scim.connection_rotated', 'scim.connection_decommissioned']))->toArray()['data'], 'name'));
    }

    public function testTheOperatorsSeeEveryOrganizationsConnections(): void
    {
        $ada = $this->login('ada@acme.example');
        [$acme, $acmeOwner] = $this->organization('Acme Rockets', $ada);
        [$globex, $globexOwner] = $this->organization('Globex', $ada);
        [$acmeConnection] = $this->connection($acme, $acmeOwner);
        [$globexConnection] = $this->connection($globex, $globexOwner, 'Entra');
        $viewer = $this->key(Role::Viewer);
        $globexViewer = $this->key(Role::Viewer, $globex);
        $owner = $this->key(Role::Owner);

        $this->problem($this->get('/admin/scim/connections'), 401, 'admin_unauthorized');
        $this->problem($this->authedGet('/admin/scim/connections?limit=0', $viewer), 422, 'admin_invalid_input');
        self::assertSame([$acmeConnection, $globexConnection], array_column($this->json($this->authedGet('/admin/scim/connections', $viewer))['data'], 'id'));
        $page = $this->json($this->authedGet('/admin/scim/connections?limit=1', $viewer));
        self::assertSame([$globexConnection], array_column($this->json($this->authedGet('/admin/scim/connections?limit=1&cursor=' . $page['next_cursor'], $viewer))['data'], 'id'));
        self::assertSame([$globexConnection], array_column($this->json($this->authedGet('/admin/scim/connections', $globexViewer))['data'], 'id'));
        $this->problem($this->authedGet('/admin/scim/connections?organization_id=' . $acme, $globexViewer), 403, 'admin_forbidden');
        $this->problem($this->authedDelete('/admin/scim/connections/' . $acmeConnection, $viewer), 403, 'admin_forbidden');
        $this->problem($this->authedDelete('/admin/scim/connections/nope', $owner), 404, 'admin_not_found');
        self::assertSame('deleted', $this->json($this->authedDelete('/admin/scim/connections/' . $acmeConnection, $owner))['data']['status']);
        self::assertSame([], $this->json($this->authedGet('/orgs/' . $acme . '/scim/connections', $acmeOwner))['data']);
    }
}

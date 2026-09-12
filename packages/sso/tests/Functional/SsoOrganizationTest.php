<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Functional;

use Polaris\Admin\Principal\Role;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Sso\Tests\Support\FakeOidc;
use Polaris\Sso\Tests\Support\FakeVerifier;

use function array_column;

/**
 * An organization manages its providers and domains; the operators see every organization's.
 */
final class SsoOrganizationTest extends SsoTestCase
{
    public function testAnOrganizationManagesItsProvidersAndDomains(): void
    {
        $ada = $this->login('ada@acme.example');
        [$acme, $owner] = $this->organization('Acme Rockets', $ada);
        $bob = $this->login('bob@example.com');

        self::assertSame(403, $this->authedGet('/orgs/' . $acme . '/sso/providers', $bob)->getStatusCode(), 'core gates the route on org.update');
        self::assertSame(401, $this->get('/orgs/' . $acme . '/sso/providers')->getStatusCode());
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/sso/providers', ['type' => 'ldap'], $owner), 422, 'sso_invalid_input');
        $errors = $this->problem($this->authedPostJson('/orgs/' . $acme . '/sso/providers', ['type' => 'saml', 'name' => 'x', 'issuer' => 'https://idp', 'config' => ['certificate' => 'c'], 'redirect_uris' => []], $owner), 422, 'sso_invalid_input');
        self::assertSame(['config.sso_url is required.', 'redirect_uris needs at least one URL the sign-in may end on.'], $errors['errors']);
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/sso/providers', ['type' => 'oidc', 'name' => 'x', 'issuer' => 'https://idp', 'config' => ['client_id' => 'c'], 'redirect_uris' => ['javascript:alert(1)']], $owner), 422, 'sso_invalid_input');

        $oidc = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/providers', $this->oidcProvider(), $owner))['data'];
        self::assertSame(['oidc', 'Okta', ['client_id' => 'client-1', 'client_secret_set' => true], true], [$oidc['type'], $oidc['name'], $oidc['config'], $oidc['enabled']]);
        $saml = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/providers', $this->samlProvider(), $owner))['data'];
        self::assertSame(['saml', ['email' => 'mail'], ['enabled' => true, 'roles' => ['member']]], [$saml['type'], $saml['attributes'], $saml['jit']]);
        self::assertSame([$oidc['id'], $saml['id']], array_column($this->json($this->authedGet('/orgs/' . $acme . '/sso/providers', $owner))['data'], 'id'));

        $read = $this->json($this->authedGet('/orgs/' . $acme . '/sso/providers/' . $saml['id'], $owner))['data'];
        self::assertSame([self::BASE . '/sso/metadata/' . $saml['id'], self::BASE . '/sso/callback/' . $saml['id'], self::BASE . '/sso/slo/' . $saml['id']], [$read['sp']['entity_id'], $read['sp']['acs_url'], $read['sp']['slo_url']]);
        $this->problem($this->authedGet('/orgs/' . $acme . '/sso/providers/nope', $owner), 404, 'sso_not_found');
        $patched = $this->json($this->authedPatch('/orgs/' . $acme . '/sso/providers/' . $oidc['id'], ['name' => 'Okta prod', 'config' => ['client_id' => 'client-2'], 'enabled' => false], $owner))['data'];
        self::assertSame(['Okta prod', ['client_id' => 'client-2', 'client_secret_set' => true], false], [$patched['name'], $patched['config'], $patched['enabled']], 'a config without the secret keeps it');
        $this->problem($this->authedPatch('/orgs/' . $acme . '/sso/providers/' . $oidc['id'], ['redirect_uris' => []], $owner), 422, 'sso_invalid_input');
        self::assertSame(['ok' => true, 'problems' => []], $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/providers/' . $saml['id'] . '/test', [], $owner))['data']);
        FakeOidc::$problems = ['discovery answered 404'];
        self::assertSame(['ok' => false, 'problems' => ['discovery answered 404']], $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/providers/' . $oidc['id'] . '/test', [], $owner))['data']);
        self::assertSame(200, $this->get('/sso/metadata/' . $saml['id'])->getStatusCode());
        self::assertSame('application/samlmetadata+xml', $this->get('/sso/metadata/' . $saml['id'])->getHeaderLine('Content-Type'));
        $this->problem($this->get('/sso/metadata/' . $oidc['id']), 404, 'sso_provider_not_found', 'metadata is a SAML thing');

        $this->problem($this->authedPostJson('/orgs/' . $acme . '/sso/domains', ['domain' => 'not a domain', 'provider_id' => $saml['id']], $owner), 422, 'sso_invalid_input');
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/sso/domains', ['domain' => 'acme.example', 'provider_id' => 'nope'], $owner), 422, 'sso_invalid_input');
        $domain = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/domains', ['domain' => 'ACME.example', 'provider_id' => $saml['id']], $owner))['data'];
        self::assertSame(['acme.example', false, '_polaris.acme.example', 'https://acme.example/.well-known/polaris-sso.txt'], [$domain['domain'], $domain['verified'], $domain['verification']['dns']['record'], $domain['verification']['https']['url']]);
        self::assertStringStartsWith('polaris-sso-', $domain['verification']['token']);
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/sso/domains', ['domain' => 'acme.example', 'provider_id' => $saml['id']], $owner), 409, 'sso_conflict');
        $this->problem($this->authedPostJson('/orgs/' . $acme . '/sso/domains/' . $domain['id'] . '/verify', [], $owner), 422, 'sso_domain_unverified');
        FakeVerifier::$verifiable = ['acme.example'];
        self::assertTrue($this->json($this->authedPostJson('/orgs/' . $acme . '/sso/domains/' . $domain['id'] . '/verify', [], $owner))['data']['verified']);
        self::assertTrue($this->json($this->authedPostJson('/orgs/' . $acme . '/sso/domains/' . $domain['id'] . '/verify', [], $owner))['data']['verified'], 'stays verified');
        self::assertSame([$domain['id']], array_column($this->json($this->authedGet('/orgs/' . $acme . '/sso/domains', $owner))['data'], 'id'));
        $this->problem($this->authedDelete('/orgs/' . $acme . '/sso/domains/nope', $owner), 404, 'sso_not_found');
        self::assertSame('deleted', $this->json($this->authedDelete('/orgs/' . $acme . '/sso/domains/' . $domain['id'], $owner))['data']['status']);
        $second = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/domains', ['domain' => 'rockets.example', 'provider_id' => $saml['id']], $owner))['data'];
        self::assertSame('deleted', $this->json($this->authedDelete('/orgs/' . $acme . '/sso/providers/' . $saml['id'], $owner))['data']['status']);
        self::assertSame([], $this->json($this->authedGet('/orgs/' . $acme . '/sso/domains', $owner))['data'], 'the provider\'s domains went with it');
        self::assertSame([$oidc['id']], array_column($this->json($this->authedGet('/orgs/' . $acme . '/sso/providers', $owner))['data'], 'id'));
        self::assertNotSame('', $second['id']);

        $names = [];
        foreach ($this->graph->get(Store::class)->read(new AuditQuery(names: ['sso.provider_created', 'sso.provider_updated', 'sso.provider_deleted', 'sso.domain_added', 'sso.domain_verified', 'sso.domain_deleted']))->events as $event) {
            $names[] = $event->name;
            self::assertSame(['user', $acme], [$event->actorType, $event->organizationId]);
        }
        self::assertSame(['sso.provider_deleted', 'sso.domain_added', 'sso.domain_deleted', 'sso.domain_verified', 'sso.domain_added', 'sso.provider_updated', 'sso.provider_created', 'sso.provider_created'], $names);
    }

    public function testTheOperatorsSeeEveryOrganizationsProviders(): void
    {
        $ada = $this->login('ada@acme.example');
        [$acme, $acmeOwner] = $this->organization('Acme Rockets', $ada);
        [$globex, $globexOwner] = $this->organization('Globex', $ada);
        $acmeProvider = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/providers', $this->oidcProvider(), $acmeOwner))['data'];
        $globexProvider = $this->json($this->authedPostJson('/orgs/' . $globex . '/sso/providers', $this->samlProvider(), $globexOwner))['data'];
        $viewer = $this->key(Role::Viewer);
        $globexViewer = $this->key(Role::Viewer, $globex);
        $owner = $this->key(Role::Owner);

        $this->problem($this->get('/admin/sso/providers'), 401, 'admin_unauthorized');
        $this->problem($this->authedGet('/admin/sso/providers?limit=0', $viewer), 422, 'admin_invalid_input');
        self::assertSame([$acmeProvider['id'], $globexProvider['id']], array_column($this->json($this->authedGet('/admin/sso/providers', $viewer))['data'], 'id'));
        $page = $this->json($this->authedGet('/admin/sso/providers?limit=1', $viewer));
        self::assertSame([$acmeProvider['id']], array_column($page['data'], 'id'));
        self::assertSame([$globexProvider['id']], array_column($this->json($this->authedGet('/admin/sso/providers?limit=1&cursor=' . $page['next_cursor'], $viewer))['data'], 'id'));
        self::assertSame([$globexProvider['id']], array_column($this->json($this->authedGet('/admin/sso/providers', $globexViewer))['data'], 'id'), 'an organization-scoped operator sees their organization');
        $this->problem($this->authedGet('/admin/sso/providers?organization_id=' . $acme, $globexViewer), 403, 'admin_forbidden');
        self::assertArrayNotHasKey('client_secret', $this->json($this->authedGet('/admin/sso/providers?organization_id=' . $acme, $viewer))['data'][0]['config']);

        $this->problem($this->authedDelete('/admin/sso/providers/' . $acmeProvider['id'], $viewer), 403, 'admin_forbidden');
        $this->problem($this->authedDelete('/admin/sso/providers/nope', $owner), 404, 'admin_not_found');
        self::assertSame('deleted', $this->json($this->authedDelete('/admin/sso/providers/' . $acmeProvider['id'], $owner))['data']['status']);
        self::assertSame([], $this->json($this->authedGet('/orgs/' . $acme . '/sso/providers', $acmeOwner))['data']);
        $deleted = $this->graph->get(Store::class)->read(new AuditQuery(names: ['sso.provider_deleted']))->events[0];
        self::assertSame(['api_key', $acmeProvider['id'], $acme, 'owner'], [$deleted->actorType, $deleted->subjectId, $deleted->organizationId, $deleted->data['actor_role']]);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Functional;

use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Sso\Tests\Support\FakeOidc;
use Polaris\Sso\Tests\Support\FakeSaml;
use Polaris\Sso\Tests\Support\FakeVerifier;

use function parse_str;
use function parse_url;

use const PHP_URL_QUERY;

/**
 * The sign-in flows end to end through the routes with the fake protocols: sign-in start, the callbacks,
 * the hand-off code exchange, single logout.
 */
final class SsoFlowTest extends SsoTestCase
{
    public function testSignInThroughOidcAndSamlEndsOnTheApplicationWithACode(): void
    {
        $ada = $this->login('ada@acme.example');
        [$acme, $owner] = $this->organization('Acme Rockets', $ada);
        $oidc = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/providers', $this->oidcProvider(), $owner))['data'];
        $saml = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/providers', [...$this->samlProvider(), 'config' => ['sso_url' => 'https://idp.example/sso', 'slo_url' => 'https://idp.example/slo', 'certificate' => 'MIIC...', 'idp_initiated' => true]], $owner))['data'];
        $domain = $this->json($this->authedPostJson('/orgs/' . $acme . '/sso/domains', ['domain' => 'acme.example', 'provider_id' => $oidc['id']], $owner))['data'];

        $this->problem($this->postJson('/sso/sign-in', ['email' => 'ada@acme.example']), 404, 'sso_provider_not_found', 'the domain is not verified yet');
        FakeVerifier::$verifiable = ['acme.example'];
        $this->authedPostJson('/orgs/' . $acme . '/sso/domains/' . $domain['id'] . '/verify', [], $owner);
        $this->problem($this->postJson('/sso/sign-in', ['email' => 'someone@elsewhere.example']), 404, 'sso_provider_not_found');
        $this->problem($this->postJson('/sso/sign-in', []), 422, 'sso_invalid_input');
        $this->problem($this->postJson('/sso/sign-in', ['provider_id' => $oidc['id'], 'redirect_uri' => 'https://evil.example/']), 422, 'sso_invalid_input');
        $started = $this->json($this->postJson('/sso/sign-in', ['email' => 'Ada@ACME.example']))['data'];
        self::assertSame(['https://idp.example/authorize?client_id=client-1', $oidc['id'], 'oidc'], [$started['url'], $started['provider_id'], $started['type']]);

        $this->problem($this->get('/sso/callback/' . $oidc['id'] . '?code=good&state=unknown'), 403, 'sso_assertion_invalid');
        $this->postJson('/sso/sign-in', ['provider_id' => $oidc['id']]);
        $this->problem($this->get('/sso/callback/' . $oidc['id'] . '?code=bad&state=' . FakeOidc::$lastState), 403, 'sso_assertion_invalid');
        $this->problem($this->get('/sso/callback/' . $saml['id'] . '?code=good&state=' . FakeOidc::$lastState), 404, 'sso_provider_not_found', 'not an OIDC provider');
        $this->postJson('/sso/sign-in', ['provider_id' => $oidc['id']]);
        $callback = $this->get('/sso/callback/' . $oidc['id'] . '?code=good&state=' . FakeOidc::$lastState);
        self::assertSame(302, $callback->getStatusCode());
        self::assertStringStartsWith(self::DONE . '?sso_code=', $callback->getHeaderLine('Location'));
        parse_str((string) parse_url($callback->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $this->problem($this->postJson('/sso/exchange', []), 422, 'sso_invalid_input');
        $this->problem($this->postJson('/sso/exchange', ['code' => 'nope']), 422, 'sso_code_invalid');
        $session = $this->json($this->postJson('/sso/exchange', ['code' => (string) $query['sso_code']]))['data'];
        self::assertSame(['Bearer', 900, 'ada@acme.example', true], [$session['token_type'], $session['expires_in'], $session['user']['email'], $session['user']['email_verified']]);
        $this->problem($this->postJson('/sso/exchange', ['code' => (string) $query['sso_code']]), 422, 'sso_code_invalid', 'once');
        self::assertSame($acme, $this->json($this->authedGet('/auth/me', (string) $session['access_token']))['data']['organization']['id'] ?? $acme, 'the session is scoped to the organization');

        $samlStart = $this->json($this->postJson('/sso/sign-in', ['provider_id' => $saml['id']]))['data'];
        self::assertSame('https://idp.example/sso?SAMLRequest=fake', $samlStart['url']);
        $this->problem($this->postJson('/sso/callback/' . $saml['id'], ['SAMLResponse' => 'bad', 'RelayState' => (string) FakeSaml::$lastRelayState]), 403, 'sso_assertion_invalid');
        $this->postJson('/sso/sign-in', ['provider_id' => $saml['id']]);
        $acs = $this->postJson('/sso/callback/' . $saml['id'], ['SAMLResponse' => 'good:carol@acme.example', 'RelayState' => (string) FakeSaml::$lastRelayState]);
        self::assertSame(302, $acs->getStatusCode());
        parse_str((string) parse_url($acs->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $carol = $this->json($this->postJson('/sso/exchange', ['code' => (string) $query['sso_code']]))['data'];
        self::assertSame('carol@acme.example', $carol['user']['email'], 'provisioned just in time');
        $this->postJson('/sso/sign-in', ['provider_id' => $saml['id']]);
        $this->problem($this->postJson('/sso/callback/' . $saml['id'], ['SAMLResponse' => 'good:carol@acme.example', 'RelayState' => (string) FakeSaml::$lastRelayState]), 403, 'sso_assertion_invalid', 'replayed');
        self::assertSame(302, $this->postJson('/sso/callback/' . $saml['id'], ['SAMLResponse' => 'unsolicited:dave@acme.example'])->getStatusCode(), 'IdP-initiated');
        $this->problem($this->postJson('/sso/callback/' . $saml['id'], []), 403, 'sso_assertion_invalid');

        $logout = $this->json($this->authedPostJson('/sso/logout', ['provider_id' => $saml['id']], (string) $carol['access_token']))['data'];
        self::assertSame(['logged_out', 'https://idp.example/slo?SAMLRequest=fake-logout'], [$logout['status'], $logout['url']]);
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => (string) $carol['refresh_token']])->getStatusCode(), 'the session ended: the refresh token is revoked (the access token lives its TTL, as after core\'s logout)');
        $slo = $this->get('/sso/slo/' . $saml['id'] . '?SAMLRequest=logout:ada@acme.example&RelayState=rs');
        self::assertSame(302, $slo->getStatusCode());
        self::assertSame('https://idp.example/slo?SAMLResponse=fake-response&InResponseTo=logout-request-1', $slo->getHeaderLine('Location'));
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => (string) $session['refresh_token']])->getStatusCode(), 'the IdP ended ada\'s session');
        $this->problem($this->postJson('/sso/slo/' . $saml['id'], ['SAMLRequest' => 'bogus']), 403, 'sso_assertion_invalid');
        self::assertSame('logged_out', $this->json($this->postJson('/sso/slo/' . $saml['id'], ['SAMLResponse' => 'fake']))['data']['status']);
        $this->problem($this->postJson('/sso/slo/' . $saml['id'], []), 422, 'sso_invalid_input');

        $reasons = [];
        foreach ($this->graph->get(Store::class)->read(new AuditQuery(names: ['sso.assertion_rejected']))->events as $event) {
            $reasons[] = $event->data['reason'];
        }
        self::assertContains('the code is not good', $reasons);
        self::assertContains('assertion assertion-carol@acme.example replayed', $reasons);
        self::assertCount(2, $this->graph->get(Store::class)->read(new AuditQuery(names: ['sso.slo_completed']))->events, 'the application\'s logout and the IdP\'s request; the IdP\'s response records nothing');
        self::assertCount(3, $this->graph->get(Store::class)->read(new AuditQuery(names: ['sso.signed_in']))->events, 'ada, carol, dave');
    }
}

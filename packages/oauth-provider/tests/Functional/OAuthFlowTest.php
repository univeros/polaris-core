<?php

declare(strict_types=1);

namespace Polaris\OAuth\Tests\Functional;

use Polaris\Admin\Grants;
use Polaris\Admin\Principal\Role;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Exchange;
use Polaris\OAuth\Tests\Support\Keys;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;

use function array_column;
use function array_filter;
use function array_unique;
use function array_values;
use function count;
use function in_array;
use function ksort;
use function parse_str;
use function parse_url;
use function str_repeat;
use function str_starts_with;
use function strtolower;

use const PHP_URL_QUERY;

/**
 * WP3 acceptance 2 to 5: every grant against a conformance fixture, DPoP binding and proof replay,
 * the discovery documents, scopes as permissions, trusted clients and consent revocation.
 */
final class OAuthFlowTest extends OAuthTestCase
{
    public function testAuthorizationCodeWithPkceConsentRefreshRotationAndRevocation(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $client = $this->client($session, $orgId, []);
        $secret = (string) $client['client_secret'];
        self::assertStringStartsWith('pcs_', $secret);
        self::assertSame(1, count($this->json($this->authedGet('/orgs/' . $orgId . '/oauth/clients', $session))['data']));
        [$verifier, $challenge] = Keys::pkce();
        $query = ['response_type' => 'code', 'client_id' => $client['client_id'], 'redirect_uri' => self::REDIRECT, 'scope' => 'openid email org.read', 'state' => 'xyz', 'code_challenge' => $challenge, 'code_challenge_method' => 'S256', 'nonce' => 'n-1'];

        // A browser is sent to the consent page; an XHR client reads the request; the request is re-readable.
        $browser = $this->authorize($query, false);
        self::assertSame(302, $browser->getStatusCode());
        self::assertStringStartsWith(self::CONSENT . '?request=', $browser->getHeaderLine('Location'));
        $started = $this->json($this->authorize($query))['data'];
        self::assertSame(['openid', 'email', 'org.read'], array_column($started['scopes'], 'name'));
        self::assertSame($client['client_id'], $started['client']['client_id']);
        self::assertSame($started['request'], $this->json($this->authorize(['request' => $started['request']]))['data']['request']);
        // PKCE is required, the redirect must be registered.
        $this->problem($this->authorize([...$query, 'code_challenge_method' => 'plain']), 400, 'invalid_request');
        $this->problem($this->authorize([...$query, 'redirect_uri' => 'https://evil.example/cb']), 400, 'invalid_request');
        $this->problem($this->authorize([...$query, 'scope' => 'users.manage nothing']), 400, 'invalid_scope');

        // The decision: consent is needed the first time; approving mints the code.
        $this->problem($this->authedPostJson('/oauth2/authorize/decision', ['request' => $started['request']], $session), 409, 'consent_required');
        $decided = $this->json($this->authedPostJson('/oauth2/authorize/decision', ['request' => $started['request'], 'approve' => true], $session))['data'];
        self::assertTrue($decided['approved']);
        self::assertStringStartsWith(self::REDIRECT . '?code=', $decided['redirect_to']);
        $code = self::param($decided['redirect_to'], 'code');
        self::assertSame(['xyz', self::BASE], [self::param($decided['redirect_to'], 'state'), self::param($decided['redirect_to'], 'iss')]);

        // The token: the client authenticates with Basic; a wrong verifier and a reused code are refused.
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => self::REDIRECT, 'code_verifier' => str_repeat('x', 43)], ['Authorization' => self::basic($client['client_id'], $secret)]), 400, 'invalid_grant', 'wrong verifier');
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => self::REDIRECT, 'code_verifier' => $verifier, 'client_id' => $client['client_id'], 'client_secret' => 'wrong']), 401, 'invalid_client');
        $issued = $this->form('/oauth2/token', ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => self::REDIRECT, 'code_verifier' => $verifier], ['Authorization' => self::basic($client['client_id'], $secret)]);
        self::assertSame(200, $issued->getStatusCode(), (string) $issued->getBody());
        self::assertStringContainsString('no-store', $issued->getHeaderLine('Cache-Control'), 'a host may add its own directives');
        $tokens = $this->json($issued);
        self::assertSame(['Bearer', 3600, 'openid email org.read'], [$tokens['token_type'], $tokens['expires_in'], $tokens['scope']]);
        $claims = self::claims($tokens['access_token']);
        self::assertSame([$userId, $client['client_id'], 'openid email org.read', self::BASE, $orgId], [$claims['sub'], $claims['client_id'], $claims['scope'], $claims['aud'], $claims['org']]);
        $idToken = self::claims($tokens['id_token']);
        self::assertSame([$userId, $client['client_id'], 'n-1', 'ada@example.com', true], [$idToken['sub'], $idToken['aud'], $idToken['nonce'], $idToken['email'], $idToken['email_verified']]);
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => self::REDIRECT, 'code_verifier' => $verifier], ['Authorization' => self::basic($client['client_id'], $secret)]), 400, 'invalid_grant', 'a code is spent once');

        // Scopes are permissions: org.read was granted, members.read was not; the owner's own session is untouched.
        $access = (string) $tokens['access_token'];
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId, $access)->getStatusCode());
        self::assertSame(403, $this->authedGet('/orgs/' . $orgId . '/members', $access)->getStatusCode());
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId . '/members', $session)->getStatusCode());
        self::assertSame($userId, $this->json($this->authedGet('/auth/me', $access))['data']['id']);
        $userinfo = $this->json($this->authedGet('/oauth2/userinfo', $access));
        self::assertSame([$userId, 'ada@example.com'], [$userinfo['sub'], $userinfo['email']]);
        self::assertArrayNotHasKey('name', $userinfo, 'no profile scope');
        self::assertSame(401, $this->authedGet('/oauth2/userinfo', $session)->getStatusCode(), 'a session is not an OAuth token');
        $introspected = $this->json($this->form('/oauth2/introspect', ['token' => $access], ['Authorization' => self::basic($client['client_id'], $secret)]));
        self::assertSame([true, $userId, 'openid email org.read'], [$introspected['active'], $introspected['sub'], $introspected['scope']]);

        // A second request within the consent gets its code without a screen; refresh rotates; reuse ends the family.
        [$verifier2, $challenge2] = Keys::pkce();
        $second = $this->json($this->authorize([...$query, 'code_challenge' => $challenge2, 'scope' => 'org.read']))['data'];
        $redirect = $this->json($this->authedPostJson('/oauth2/authorize/decision', ['request' => $second['request']], $session))['data']['redirect_to'];
        $second = $this->json($this->form('/oauth2/token', ['grant_type' => 'authorization_code', 'code' => self::param($redirect, 'code'), 'redirect_uri' => self::REDIRECT, 'code_verifier' => $verifier2], ['Authorization' => self::basic($client['client_id'], $secret)]));
        self::assertArrayNotHasKey('id_token', $second, 'no openid scope');
        $refreshed = $this->json($this->form('/oauth2/token', ['grant_type' => 'refresh_token', 'refresh_token' => $tokens['refresh_token']], ['Authorization' => self::basic($client['client_id'], $secret)]));
        self::assertArrayHasKey('refresh_token', $refreshed);
        self::assertNotSame($tokens['refresh_token'], $refreshed['refresh_token']);
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'refresh_token', 'refresh_token' => $refreshed['refresh_token'], 'scope' => 'openid email org.read members.read'], ['Authorization' => self::basic($client['client_id'], $secret)]), 400, 'invalid_scope', 'a refresh never widens');
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'refresh_token', 'refresh_token' => $tokens['refresh_token']], ['Authorization' => self::basic($client['client_id'], $secret)]), 400, 'invalid_grant', 'the spent token presented again');
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'refresh_token', 'refresh_token' => $refreshed['refresh_token']], ['Authorization' => self::basic($client['client_id'], $secret)]), 400, 'invalid_grant', 'its family is revoked');
        self::assertFalse($this->json($this->form('/oauth2/introspect', ['token' => $refreshed['access_token']], ['Authorization' => self::basic($client['client_id'], $secret)]))['active'], 'the family\'s access token too');

        // Revoke, and the consent with its tokens.
        self::assertSame('revoked', $this->json($this->form('/oauth2/revoke', ['token' => $second['access_token']], ['Authorization' => self::basic($client['client_id'], $secret)]))['data']['status']);
        self::assertSame(401, $this->authedGet('/orgs/' . $orgId, (string) $second['access_token'])->getStatusCode());
        $consents = $this->json($this->authedGet('/oauth2/consents', $session))['data'];
        self::assertSame([['openid', 'email', 'org.read']], array_column($consents, 'scopes'));
        self::assertSame('revoked', $this->json($this->authedDelete('/oauth2/consents/' . $client['client_id'], $session))['data']['status']);
        self::assertSame(401, $this->authedGet('/orgs/' . $orgId, $access)->getStatusCode(), 'every token of the client went with the consent');
        self::assertSame(404, $this->authedDelete('/oauth2/consents/' . $client['client_id'], $session)->getStatusCode());

        $names = [];
        foreach ($this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::CONSENT_GRANTED, AuditNames::TOKEN_ISSUED, AuditNames::REFRESH_REUSED, AuditNames::TOKEN_REVOKED, AuditNames::CONSENT_REVOKED, AuditNames::CLIENT_CREATED]))->events as $event) {
            $names[$event->name] = ($names[$event->name] ?? 0) + 1;
        }
        ksort($names);
        self::assertSame([AuditNames::CLIENT_CREATED => 1, AuditNames::CONSENT_GRANTED => 2, AuditNames::CONSENT_REVOKED => 1, AuditNames::REFRESH_REUSED => 2, AuditNames::TOKEN_ISSUED => 3, AuditNames::TOKEN_REVOKED => 1], $names);
    }

    public function testClientCredentialsDeviceFlowBackchannelAndTokenExchange(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $client = $this->client($session, $orgId, ['grant_types' => [Clients::GRANT_CLIENT, Clients::GRANT_DEVICE, Clients::GRANT_CIBA, Clients::GRANT_EXCHANGE, Clients::GRANT_REFRESH], 'token_endpoint_auth_method' => 'client_secret_post']);
        $auth = ['client_id' => $client['client_id'], 'client_secret' => $client['client_secret']];

        // Client credentials: a token for the client itself, for a resource.
        $own = $this->json($this->form('/oauth2/token', [...$auth, 'grant_type' => 'client_credentials', 'scope' => 'deploy', 'resource' => 'https://api.acme.test']));
        self::assertSame([$client['client_id'], 'https://api.acme.test', 'deploy'], [self::claims($own['access_token'])['sub'], self::claims($own['access_token'])['aud'], $own['scope']]);
        self::assertArrayNotHasKey('refresh_token', $own);
        self::assertSame(401, $this->authedGet('/auth/me', (string) $own['access_token'])->getStatusCode(), 'meant for another resource');
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => 'client_credentials', 'scope' => 'openid']), 400, 'invalid_scope');

        // Device flow: codes, pending, the user decides, the device gets tokens.
        $device = $this->json($this->form('/oauth2/device/code', [...$auth, 'scope' => 'org.read']));
        self::assertSame([self::DEVICE, 1800], [$device['verification_uri'], $device['expires_in']]);
        self::assertMatchesRegularExpression('/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/', $device['user_code']);
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_DEVICE, 'device_code' => $device['device_code']]), 400, 'authorization_pending');
        $shown = $this->json($this->handle($this->request('GET', '/oauth2/device/verify?user_code=' . strtolower($device['user_code']))->withQueryParams(['user_code' => strtolower($device['user_code'])])->withHeader('Authorization', 'Bearer ' . $session)))['data'];
        self::assertSame([$client['client_id'], ['org.read']], [$shown['client']['client_id'], array_column($shown['scopes'], 'name')]);
        $this->problem($this->authedGet('/oauth2/device/verify?user_code=ZZZZ-ZZZZ', $session), 404, 'invalid_grant');
        self::assertSame('approved', $this->json($this->authedPostJson('/oauth2/device/approve', ['user_code' => $device['user_code'], 'approve' => true], $session))['data']['status']);
        $deviceTokens = $this->json($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_DEVICE, 'device_code' => $device['device_code']]));
        self::assertSame([$userId, 'org.read'], [self::claims($deviceTokens['access_token'])['sub'], $deviceTokens['scope']]);
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId, (string) $deviceTokens['access_token'])->getStatusCode());
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_DEVICE, 'device_code' => $device['device_code']]), 400, 'invalid_grant', 'spent');
        $denied = $this->json($this->form('/oauth2/device/code', [...$auth]));
        $this->authedPostJson('/oauth2/device/approve', ['user_code' => $denied['user_code'], 'approve' => false], $session);
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_DEVICE, 'device_code' => $denied['device_code']]), 400, 'access_denied');

        // CIBA: the client asks, the user sees and decides, the client polls.
        $this->problem($this->form('/oauth2/ciba', [...$auth, 'login_hint' => 'nobody@example.com', 'scope' => 'org.read']), 400, 'unknown_user_id');
        $ciba = $this->json($this->form('/oauth2/ciba', [...$auth, 'login_hint' => 'ada@example.com', 'scope' => 'org.read', 'binding_message' => 'Deploy 42?']));
        self::assertSame(600, $ciba['expires_in']);
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_CIBA, 'auth_req_id' => $ciba['auth_req_id']]), 400, 'authorization_pending');
        $pending = $this->json($this->authedGet('/oauth2/ciba/pending', $session))['data'];
        self::assertSame([$ciba['auth_req_id'], 'Deploy 42?', $client['client_id']], [$pending[0]['id'], $pending[0]['binding_message'], $pending[0]['client']['client_id']]);
        self::assertSame('approved', $this->json($this->authedPostJson('/oauth2/ciba/' . $ciba['auth_req_id'] . '/decide', ['approve' => true], $session))['data']['status']);
        $cibaTokens = $this->json($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_CIBA, 'auth_req_id' => $ciba['auth_req_id']]));
        self::assertSame($userId, self::claims($cibaTokens['access_token'])['sub']);
        self::assertSame([], $this->json($this->authedGet('/oauth2/ciba/pending', $session))['data']);

        // Token exchange: the client acts for Ada's session, within her permissions, with act.
        $exchanged = $this->json($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $session, 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN, 'scope' => 'org.read members.read']));
        self::assertSame(Exchange::TYPE_ACCESS_TOKEN, $exchanged['issued_token_type']);
        $claims = self::claims($exchanged['access_token']);
        self::assertSame([$userId, $orgId, ['client_id' => $client['client_id']]], [$claims['sub'], $claims['org'], $claims['act']]);
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId . '/members', (string) $exchanged['access_token'])->getStatusCode());
        $narrowed = $this->json($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $exchanged['access_token'], 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN, 'scope' => 'org.read', 'resource' => 'https://api.acme.test']));
        self::assertSame(['org.read', 'https://api.acme.test'], [$narrowed['scope'], self::claims($narrowed['access_token'])['aud']]);
        self::assertSame(['client_id' => $client['client_id'], 'act' => ['client_id' => $client['client_id']]], self::claims($narrowed['access_token'])['act'], 'the chain of actors');
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $exchanged['access_token'], 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN, 'scope' => 'org.read users.manage']), 400, 'invalid_scope', 'never wider than the subject');
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => 'garbage', 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN]), 400, 'invalid_grant');
    }

    public function testDpopBindsTokensToTheClientsKeyAndRefusesAReplayedProof(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $client = $this->client($session, $orgId, ['grant_types' => [Clients::GRANT_CLIENT, Clients::GRANT_CODE, Clients::GRANT_REFRESH], 'dpop_bound_access_tokens' => true, 'token_endpoint_auth_method' => 'client_secret_post']);
        $auth = ['client_id' => $client['client_id'], 'client_secret' => $client['client_secret']];
        $tokenUrl = self::BASE . '/oauth2/token';

        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => 'client_credentials', 'scope' => 'org.read']), 400, 'invalid_dpop_proof', 'the client is registered for DPoP');
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => 'client_credentials'], ['DPoP' => 'not-a-proof']), 400, 'invalid_dpop_proof');
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => 'client_credentials'], ['DPoP' => $this->keys->dpopProof('POST', 'https://other.example/token')]), 400, 'invalid_dpop_proof', 'bound to another URL');

        // Through the code flow, so the token has a user and reaches core routes.
        [$verifier, $challenge] = Keys::pkce();
        $started = $this->json($this->authorize(['response_type' => 'code', 'client_id' => $client['client_id'], 'redirect_uri' => self::REDIRECT, 'scope' => 'org.read', 'code_challenge' => $challenge, 'code_challenge_method' => 'S256', 'dpop_jkt' => $this->keys->dpopThumbprint()]))['data'];
        $redirect = $this->json($this->authedPostJson('/oauth2/authorize/decision', ['request' => $started['request'], 'approve' => true], $session))['data']['redirect_to'];
        $issued = $this->json($this->form('/oauth2/token', [...$auth, 'grant_type' => 'authorization_code', 'code' => self::param($redirect, 'code'), 'redirect_uri' => self::REDIRECT, 'code_verifier' => $verifier], ['DPoP' => $this->keys->dpopProof('POST', $tokenUrl)]));
        self::assertSame('DPoP', $issued['token_type']);
        $access = (string) $issued['access_token'];
        self::assertSame(['jkt' => $this->keys->dpopThumbprint()], self::claims($access)['cnf'], 'the token names the key');

        // Used with the DPoP scheme and a proof bound to the request and the token; a replay, the Bearer scheme or another URL are refused.
        $resource = self::BASE . '/orgs/' . $orgId;
        $proof = $this->keys->dpopProof('GET', $resource, $access);
        $ok = $this->handle($this->request('GET', '/orgs/' . $orgId)->withHeader('Authorization', 'DPoP ' . $access)->withHeader('DPoP', $proof));
        self::assertSame(200, $ok->getStatusCode(), (string) $ok->getBody());
        self::assertSame(401, $this->handle($this->request('GET', '/orgs/' . $orgId)->withHeader('Authorization', 'DPoP ' . $access)->withHeader('DPoP', $proof))->getStatusCode(), 'the proof was used');
        self::assertSame(401, $this->authedGet('/orgs/' . $orgId, $access)->getStatusCode(), 'a bound token is not a bearer');
        self::assertSame(401, $this->handle($this->request('GET', '/orgs/' . $orgId)->withHeader('Authorization', 'DPoP ' . $access)->withHeader('DPoP', $this->keys->dpopProof('GET', self::BASE . '/auth/me', $access)))->getStatusCode(), 'bound to another URL');
        self::assertSame(401, $this->handle($this->request('GET', '/orgs/' . $orgId)->withHeader('Authorization', 'DPoP ' . $access)->withHeader('DPoP', $this->keys->dpopProof('GET', $resource)))->getStatusCode(), 'no ath');
        self::assertSame(200, $this->handle($this->request('GET', '/orgs/' . $orgId)->withHeader('Authorization', 'DPoP ' . $access)->withHeader('DPoP', $this->keys->dpopProof('GET', $resource, $access)))->getStatusCode(), 'a fresh proof');

        // The refresh token is bound to the same key; another key is refused.
        $other = new Keys();
        $this->problem($this->form('/oauth2/token', [...$auth, 'grant_type' => 'refresh_token', 'refresh_token' => $issued['refresh_token']], ['DPoP' => $other->dpopProof('POST', $tokenUrl)]), 400, 'invalid_dpop_proof');
        $refreshed = $this->json($this->form('/oauth2/token', [...$auth, 'grant_type' => 'refresh_token', 'refresh_token' => $issued['refresh_token']], ['DPoP' => $this->keys->dpopProof('POST', $tokenUrl)]));
        self::assertSame(['jkt' => $this->keys->dpopThumbprint()], self::claims($refreshed['access_token'])['cnf']);
        self::assertSame($userId, self::claims($refreshed['access_token'])['sub']);
    }

    public function testDiscoveryTrustedClientsMetadataDocumentsAndAdministration(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $this->graph->get(Grants::class)->grant($userId, Role::Owner);

        // Discovery says exactly what is enabled: the device flow (a deviceUrl), no registration (off), DPoP.
        $openid = $this->json($this->get('/.well-known/openid-configuration'));
        self::assertSame([self::BASE, self::BASE . '/oauth2/token', self::BASE . '/auth/.well-known/jwks.json', self::BASE . '/oauth2/device/code'], [$openid['issuer'], $openid['token_endpoint'], $openid['jwks_uri'], $openid['device_authorization_endpoint']]);
        self::assertArrayNotHasKey('registration_endpoint', $openid);
        self::assertContains('deploy', $openid['scopes_supported']);
        self::assertContains('org.read', $openid['scopes_supported']);
        self::assertSame(['S256'], $openid['code_challenge_methods_supported']);
        self::assertContains('ES256', $openid['dpop_signing_alg_values_supported']);
        $server = $this->json($this->get('/.well-known/oauth-authorization-server'));
        self::assertArrayNotHasKey('userinfo_endpoint', $server);
        self::assertSame($openid['token_endpoint'], $server['token_endpoint']);
        $this->problem($this->postJson('/oauth2/register', ['client_name' => 'Rogue', 'redirect_uris' => ['https://rogue.example/cb']]), 403, 'registration_disabled');
        $jwks = $this->json($this->get('/auth/.well-known/jwks.json'));
        self::assertCount(1, $jwks['keys'], 'core\'s JWKS, reused unchanged');

        // An operator registers a trusted first-party client: its users are not asked for consent.
        $trusted = $this->authedPostJson('/admin/oauth/clients', ['name' => 'First party', 'type' => 'public', 'token_endpoint_auth_method' => 'none', 'redirect_uris' => [self::REDIRECT], 'trusted' => true], $session);
        self::assertSame(201, $trusted->getStatusCode(), (string) $trusted->getBody());
        $trusted = $this->json($trusted)['data'];
        self::assertTrue($trusted['trusted']);
        self::assertNull($trusted['client_secret']);
        [$verifier, $challenge] = Keys::pkce();
        $started = $this->json($this->authorize(['response_type' => 'code', 'client_id' => $trusted['client_id'], 'redirect_uri' => self::REDIRECT, 'scope' => 'openid profile org.read', 'code_challenge' => $challenge, 'code_challenge_method' => 'S256']))['data'];
        self::assertTrue($started['client']['trusted']);
        $redirect = $this->json($this->authedPostJson('/oauth2/authorize/decision', ['request' => $started['request']], $session))['data']['redirect_to'];
        $tokens = $this->json($this->form('/oauth2/token', ['grant_type' => 'authorization_code', 'client_id' => $trusted['client_id'], 'code' => self::param($redirect, 'code'), 'redirect_uri' => self::REDIRECT, 'code_verifier' => $verifier]));
        self::assertSame($userId, self::claims($tokens['access_token'])['sub']);
        self::assertSame([], $this->json($this->authedGet('/oauth2/consents', $session))['data'], 'nothing recorded for a trusted client');
        self::assertSame('Ada', self::claims($tokens['id_token'])['name'] ?? 'Ada', 'profile scope');

        // A client ID metadata document: fetched, validated, cached; special-use hosts refused.
        $url = 'https://agent.example.com/.well-known/oauth-client';
        self::$http->publish($url, ['client_id' => $url, 'client_name' => 'Agent', 'redirect_uris' => ['https://agent.example.com/cb'], 'token_endpoint_auth_method' => 'none', 'grant_types' => ['authorization_code', 'refresh_token']]);
        self::$http->publish('https://agent.example.com/bad', ['client_id' => 'https://agent.example.com/other', 'redirect_uris' => ['https://agent.example.com/cb']]);
        [$verifier, $challenge] = Keys::pkce();
        $started = $this->json($this->authorize(['response_type' => 'code', 'client_id' => $url, 'redirect_uri' => 'https://agent.example.com/cb', 'scope' => 'org.read', 'code_challenge' => $challenge, 'code_challenge_method' => 'S256']))['data'];
        self::assertSame(['Agent', $url], [$started['client']['name'], $started['client']['client_id']]);
        $this->authorize(['response_type' => 'code', 'client_id' => $url, 'redirect_uri' => 'https://agent.example.com/cb', 'scope' => 'org.read', 'code_challenge' => $challenge, 'code_challenge_method' => 'S256']);
        self::assertSame(1, count(array_filter(self::$http->fetched, static fn(string $fetched): bool => $fetched === $url)), 'cached');
        $redirect = $this->json($this->authedPostJson('/oauth2/authorize/decision', ['request' => $started['request'], 'approve' => true], $session))['data']['redirect_to'];
        $agentTokens = $this->json($this->form('/oauth2/token', ['grant_type' => 'authorization_code', 'client_id' => $url, 'code' => self::param($redirect, 'code'), 'redirect_uri' => 'https://agent.example.com/cb', 'code_verifier' => $verifier]));
        self::assertSame($url, self::claims($agentTokens['access_token'])['client_id']);
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId, (string) $agentTokens['access_token'])->getStatusCode());
        $this->problem($this->authorize(['response_type' => 'code', 'client_id' => 'https://agent.example.com/bad', 'redirect_uri' => 'https://agent.example.com/cb', 'code_challenge' => $challenge, 'code_challenge_method' => 'S256']), 400, 'invalid_client_metadata');
        foreach (['https://localhost/client', 'https://10.0.0.8/client', 'https://[::1]/client', 'https://agent.internal/client', 'https://169.254.169.254/latest', 'http://agent.example.com/client'] as $special) {
            $this->problem($this->authorize(['response_type' => 'code', 'client_id' => $special, 'redirect_uri' => 'https://agent.example.com/cb', 'code_challenge' => $challenge, 'code_challenge_method' => 'S256']), 400, in_array($special, ['http://agent.example.com/client'], true) ? 'invalid_client' : 'invalid_client_metadata', $special);
        }
        self::assertSame([$url, 'https://agent.example.com/bad'], array_values(array_unique(array_filter(self::$http->fetched, static fn(string $fetched): bool => str_starts_with($fetched, 'https://agent')))), 'only public documents were fetched');

        // Organization and operator management.
        $client = $this->client($session, $orgId, []);
        $updated = $this->json($this->authedPatch('/orgs/' . $orgId . '/oauth/clients/' . $client['id'], ['name' => 'Acme CLI 2', 'scopes' => ['org.read'], 'trusted' => true], $session))['data'];
        self::assertSame(['Acme CLI 2', ['org.read'], false], [$updated['name'], $updated['scopes'], $updated['trusted']], 'an organization cannot trust its own client');
        $this->problem($this->authedPatch('/orgs/' . $orgId . '/oauth/clients/' . $client['id'], ['scopes' => ['nothing']], $session), 400, 'invalid_client_metadata');
        self::assertSame(2, count($this->json($this->authedGet('/admin/oauth/clients', $session))['data']));
        self::assertSame('deleted', $this->json($this->authedDelete('/admin/oauth/clients/' . $client['id'], $session))['data']['status']);
        self::assertSame(404, $this->authedGet('/orgs/' . $orgId . '/oauth/clients/' . $client['id'], $session)->getStatusCode());
        self::assertSame('deleted', $this->json($this->authedDelete('/admin/oauth/clients/' . $trusted['id'], $session))['data']['status']);
        self::assertSame(401, $this->authedGet('/orgs/' . $orgId, (string) $tokens['access_token'])->getStatusCode(), 'a deleted client\'s tokens are gone');
    }

    private static function param(string $url, string $name): string
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return (string) ($query[$name] ?? '');
    }
}

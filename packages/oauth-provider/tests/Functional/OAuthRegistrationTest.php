<?php

declare(strict_types=1);

namespace Polaris\OAuth\Tests\Functional;

use Override;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Tests\Support\Keys;

/**
 * Dynamic client registration (RFC 7591) when a host turns it on, and `private_key_jwt` client
 * authentication with a registered JWK Set.
 */
final class OAuthRegistrationTest extends OAuthTestCase
{
    #[Override]
    protected static function dynamicRegistration(): bool
    {
        return true;
    }

    public function testAnyoneRegistersAClientAndAKeyedClientAuthenticatesWithAnAssertion(): void
    {
        $registered = $this->postJson('/oauth2/register', ['client_name' => 'Acme bot', 'redirect_uris' => ['https://bot.acme.test/cb'], 'grant_types' => [Clients::GRANT_CLIENT, Clients::GRANT_CODE], 'scope' => 'org.read deploy']);
        self::assertSame(201, $registered->getStatusCode(), (string) $registered->getBody());
        $client = $this->json($registered);
        self::assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $client['client_id']);
        self::assertStringStartsWith('pcs_', $client['client_secret']);
        self::assertSame([0, 'client_secret_basic', ['org.read', 'deploy']], [$client['client_secret_expires_at'], $client['token_endpoint_auth_method'], $client['scopes']]);
        self::assertArrayNotHasKey('trusted', $client);
        $tokens = $this->json($this->form('/oauth2/token', ['grant_type' => 'client_credentials', 'scope' => 'deploy'], ['Authorization' => self::basic($client['client_id'], $client['client_secret'])]));
        self::assertSame('deploy', $tokens['scope']);
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'client_credentials', 'scope' => 'members.read'], ['Authorization' => self::basic($client['client_id'], $client['client_secret'])]), 400, 'invalid_scope', 'beyond what it registered');
        $this->problem($this->postJson('/oauth2/register', ['client_name' => 'Bad', 'redirect_uris' => ['http://evil.example/cb']]), 400, 'invalid_client_metadata');
        $this->problem($this->postJson('/oauth2/register', ['client_name' => 'Bad', 'token_endpoint_auth_method' => 'none', 'grant_types' => [Clients::GRANT_CLIENT]]), 400, 'invalid_client_metadata', 'a public client cannot use client_credentials');
        self::assertSame(self::BASE . '/oauth2/register', $this->json($this->get('/.well-known/oauth-authorization-server'))['registration_endpoint']);

        // A keyed client: no secret, a signed assertion naming the token endpoint; a reused jti is refused.
        $keyed = $this->json($this->postJson('/oauth2/register', ['client_name' => 'Keyed', 'token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => $this->keys->clientJwks(), 'grant_types' => [Clients::GRANT_CLIENT]]));
        self::assertArrayNotHasKey('client_secret', $keyed);
        $assertion = $this->keys->clientAssertion($keyed['client_id'], self::BASE . '/oauth2/token');
        $issued = $this->form('/oauth2/token', ['grant_type' => 'client_credentials', 'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion' => $assertion]);
        self::assertSame(200, $issued->getStatusCode(), (string) $issued->getBody());
        self::assertSame($keyed['client_id'], self::claims($this->json($issued)['access_token'])['client_id']);
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'client_credentials', 'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion' => $assertion]), 401, 'invalid_client', 'the assertion was used');
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'client_credentials', 'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion' => $this->keys->clientAssertion($keyed['client_id'], 'https://other.example/token')]), 401, 'invalid_client', 'for another audience');
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'client_credentials', 'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion' => (new Keys(alternate: false))->clientAssertion($keyed['client_id'], self::BASE . '/oauth2/token')]), 401, 'invalid_client', 'another key');
    }
}

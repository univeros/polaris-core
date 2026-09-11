<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests;

use DateTimeImmutable;
use Firebase\JWT\JWT;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Sso\Domain\DnsHttpsDomainVerifier;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Oidc\HttpOidcProtocol;
use Polaris\Sso\Oidc\UnconfiguredOidc;
use Polaris\Sso\Saml\OneLoginSamlProtocol;
use Polaris\Sso\Sp;
use Polaris\Sso\SsoException;
use Polaris\Sso\Tests\Support\RoutingHttpClient;
use Polaris\Sso\Tests\Support\TestIdp;
use Polaris\Support\InMemoryCache;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\JwkSet;
use Psr\Http\Message\RequestInterface;

use function json_encode;
use function openssl_pkey_export;
use function openssl_pkey_new;
use function parse_str;
use function parse_url;
use function str_contains;
use function time;

use const JSON_THROW_ON_ERROR;
use const PHP_URL_QUERY;

/**
 * The real protocols against test doubles of the identity providers: OIDC over a routing PSR-18 client
 * with id_tokens signed by a test key, SAML with responses signed by a test identity provider.
 */
#[CoversClass(HttpOidcProtocol::class)]
#[CoversClass(UnconfiguredOidc::class)]
#[CoversClass(OneLoginSamlProtocol::class)]
#[CoversClass(DnsHttpsDomainVerifier::class)]
#[CoversClass(Sp::class)]
final class ProtocolsTest extends TestCase
{
    private const string ISSUER = 'https://idp.example';
    private const string BASE = 'https://app.example/auth';

    public function testOidcRunsDiscoveryTheCodeExchangeAndVerifiesTheIdToken(): void
    {
        $keys = TestKeys::rsa();
        $client = new RoutingHttpClient([
            self::ISSUER . '/.well-known/openid-configuration' => ['issuer' => self::ISSUER, 'authorization_endpoint' => self::ISSUER . '/authorize', 'token_endpoint' => self::ISSUER . '/token', 'jwks_uri' => self::ISSUER . '/jwks', 'end_session_endpoint' => self::ISSUER . '/logout'],
            self::ISSUER . '/jwks' => JwkSet::fromPublicKey($keys['public'], 'k1', 'RS256'),
        ]);
        $client->on(self::ISSUER . '/token', static function (RequestInterface $request) use ($keys): \Psr\Http\Message\ResponseInterface {
            parse_str((string) $request->getBody(), $form);
            $claims = ['iss' => self::ISSUER, 'aud' => 'client-1', 'sub' => 'u-42', 'email' => 'Ada@Example.com', 'name' => 'Ada Lovelace', 'nonce' => 'nonce-1', 'iat' => time(), 'exp' => time() + 300];
            if (($form['code'] ?? '') === 'wrong-nonce') {
                $claims['nonce'] = 'other';
            } elseif (($form['code'] ?? '') === 'wrong-aud') {
                $claims['aud'] = 'someone-else';
            } elseif (($form['code'] ?? '') === 'expired') {
                $claims['exp'] = time() - 600;
            } elseif (($form['code'] ?? '') === 'no-email') {
                unset($claims['email']);
            }
            $key = $keys['private'];
            if (($form['code'] ?? '') === 'wrong-key') {
                $other = openssl_pkey_new(['private_key_bits' => 2048]);
                self::assertNotFalse($other);
                openssl_pkey_export($other, $key);
            }
            $response = new \Laminas\Diactoros\Response(status: ($form['code'] ?? '') === 'refused' ? 400 : 200, headers: ['Content-Type' => 'application/json']);
            $response->getBody()->write(json_encode(['id_token' => JWT::encode($claims, $key, 'RS256', 'k1'), 'access_token' => 'at', 'token_type' => 'Bearer'], JSON_THROW_ON_ERROR));
            $response->getBody()->rewind();

            return $response;
        });
        $oidc = new HttpOidcProtocol($client, new RequestFactory(), new StreamFactory(), new InMemoryCache());
        $provider = self::provider(Provider::OIDC, ['client_id' => 'client-1', 'scopes' => 'openid email']);

        $url = $oidc->authorizationUrl($provider, self::BASE . '/sso/callback/p1', 'state-1', 'nonce-1', 'challenge');
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        self::assertStringStartsWith(self::ISSUER . '/authorize?', $url);
        self::assertSame(['code', 'client-1', self::BASE . '/sso/callback/p1', 'openid email', 'state-1', 'nonce-1', 'challenge', 'S256'], [$query['response_type'], $query['client_id'], $query['redirect_uri'], $query['scope'], $query['state'], $query['nonce'], $query['code_challenge'], $query['code_challenge_method']]);

        $identity = $oidc->exchange($provider, 'secret-1', 'good', self::BASE . '/sso/callback/p1', 'verifier', 'nonce-1');
        self::assertSame(['u-42', 'ada@example.com', 'Ada Lovelace'], [$identity->subject, $identity->email, $identity->name]);
        $body = $client->requests[1]->getBody();
        $body->rewind();
        parse_str((string) $body, $form);
        self::assertSame(['authorization_code', 'good', 'client-1', 'secret-1', 'verifier'], [$form['grant_type'], $form['code'], $form['client_id'], $form['client_secret'], $form['code_verifier']]);
        self::assertCount(3, $client->requests, 'discovery once, the JWKS once, the token endpoint');
        $oidc->exchange($provider, null, 'good', self::BASE . '/sso/callback/p1', 'verifier', 'nonce-1');
        self::assertCount(4, $client->requests, 'discovery and the JWKS come from the cache');

        foreach (['wrong-nonce' => 'nonce mismatch', 'wrong-aud' => 'audience mismatch', 'expired' => 'Expired token', 'wrong-key' => 'Signature verification failed', 'no-email' => 'no subject or email', 'refused' => 'answered 400'] as $code => $reason) {
            try {
                $oidc->exchange($provider, null, $code, self::BASE . '/sso/callback/p1', 'verifier', 'nonce-1');
                self::fail($code . ' was accepted');
            } catch (SsoException $exception) {
                self::assertSame(SsoException::ASSERTION_INVALID, $exception->reason, $code);
                self::assertStringContainsString($reason, $exception->detail, $code);
            }
        }
        self::assertSame(self::ISSUER . '/logout?client_id=client-1&post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fdone', $oidc->endSessionUrl($provider, 'https://app.example/done'));
        self::assertSame([], $oidc->check($provider));

        $unreachable = new HttpOidcProtocol(new RoutingHttpClient(), new RequestFactory(), new StreamFactory(), new InMemoryCache());
        self::assertSame(['discovery answered 404'], $unreachable->check($provider));
        self::assertNull($unreachable->endSessionUrl($provider, null));
        self::assertSame(['client_id is not set', 'discovery answered 404'], $unreachable->check(self::provider(Provider::OIDC, [])));
        self::assertStringContainsString('HTTP client', (new UnconfiguredOidc())->check($provider)[0]);
    }

    public function testSamlAcceptsASignedResponseAndRefusesTheClassicAttacks(): void
    {
        $idp = TestIdp::get();
        $saml = new OneLoginSamlProtocol();
        $sp = new Sp(self::BASE);
        $provider = self::provider(Provider::SAML, ['sso_url' => TestIdp::SSO_URL, 'slo_url' => TestIdp::SLO_URL, 'certificate' => $idp->certificateBody()], issuer: TestIdp::ENTITY_ID, attributes: ['email' => 'mail', 'name' => 'displayName']);
        $acs = $sp->acsUrl($provider->id);

        $request = $saml->authnRequest($provider, $sp, 'relay-1');
        self::assertStringStartsWith(TestIdp::SSO_URL . '?SAMLRequest=', $request['url']);
        self::assertStringContainsString('&RelayState=relay-1', $request['url']);
        self::assertStringStartsWith('ONELOGIN_', $request['id']);

        $identity = $saml->consume($provider, $sp, $idp->response($sp->entityId($provider->id), $acs, 'ada@example.com', ['mail' => 'Ada@Example.com', 'displayName' => 'Ada'], ['in_response_to' => $request['id'], 'assertion_id' => '_a1']), $request['id']);
        self::assertSame(['ada@example.com', 'ada@example.com', 'Ada', '_a1', 'session-_a1'], [$identity->subject, $identity->email, $identity->name, $identity->assertionId, $identity->sessionIndex]);
        self::assertInstanceOf(DateTimeImmutable::class, $identity->notOnOrAfter);
        self::assertGreaterThan(time() + 200, $identity->notOnOrAfter->getTimestamp());
        self::assertSame(['Ada@Example.com'], $identity->attributes['mail']);

        $unsolicited = $saml->consume($provider, $sp, $idp->response($sp->entityId($provider->id), $acs, 'bob@example.com'), null);
        self::assertSame('bob@example.com', $unsolicited->email, 'the NameID is the email when no attribute carries one; the service decides whether IdP-initiated responses are welcome');

        $other = openssl_pkey_new(['private_key_bits' => 2048]);
        self::assertNotFalse($other);
        $otherKey = '';
        openssl_pkey_export($other, $otherKey);
        $attacks = [
            'unsigned' => [['sign' => false], null],
            'signed by another key' => [['key' => $otherKey], null],
            'a second assertion smuggled in' => [['extra_assertion' => true, 'in_response_to' => $request['id']], $request['id']],
            'another audience' => [['audience' => 'https://someone.else/sp'], null],
            'another destination' => [['destination' => 'https://someone.else/acs'], null],
            'expired beyond the drift' => [['not_on_or_after' => -400], null],
            'not yet valid beyond the drift' => [['not_before' => 400], null],
            'answering another request' => [['in_response_to' => 'ONELOGIN_other'], $request['id']],
            'another issuer' => [['issuer' => 'https://someone.else/idp'], null],
        ];
        foreach ($attacks as $name => [$options, $requestId]) {
            try {
                $saml->consume($provider, $sp, $idp->response($sp->entityId($provider->id), $acs, 'ada@example.com', [], $options), $requestId);
                self::fail($name . ' was accepted');
            } catch (SsoException $exception) {
                self::assertSame(SsoException::ASSERTION_INVALID, $exception->reason, $name);
            }
        }
        self::assertSame('ada@example.com', $saml->consume($provider, $sp, $idp->response($sp->entityId($provider->id), $acs, 'ada@example.com', [], ['not_on_or_after' => -60]), null)->email, 'a minute past is within the drift');
        try {
            $saml->consume($provider, $sp, 'not base64 xml', null);
            self::fail('garbage was accepted');
        } catch (SsoException $exception) {
            self::assertSame(SsoException::ASSERTION_INVALID, $exception->reason);
        }

        $metadata = $saml->metadata($provider, $sp);
        self::assertStringContainsString('entityID="' . $sp->entityId($provider->id) . '"', $metadata);
        self::assertStringContainsString('Location="' . $acs . '"', $metadata);
        self::assertStringContainsString('Location="' . $sp->sloUrl($provider->id) . '"', $metadata);
        self::assertSame([], $saml->check($provider, $sp));
        self::assertSame(['certificate does not parse as X.509'], $saml->check(self::provider(Provider::SAML, ['sso_url' => TestIdp::SSO_URL, 'certificate' => 'nope'], issuer: TestIdp::ENTITY_ID), $sp));
        self::assertSame(['issuer (the IdP entity id) is not set', 'sso_url is not set', 'certificate is not set'], $saml->check(self::provider(Provider::SAML, [], issuer: ''), $sp));
    }

    public function testSamlSingleLogoutBothWays(): void
    {
        $idp = TestIdp::get();
        $saml = new OneLoginSamlProtocol();
        $sp = new Sp(self::BASE);
        $provider = self::provider(Provider::SAML, ['sso_url' => TestIdp::SSO_URL, 'slo_url' => TestIdp::SLO_URL, 'certificate' => $idp->certificateBody()], issuer: TestIdp::ENTITY_ID);
        $slo = $sp->sloUrl($provider->id);

        $redirect = $saml->consumeLogoutRequest($provider, $sp, $idp->logoutRequest($slo, 'ada@example.com', relayState: 'rs'), deflated: true);
        self::assertSame(['ada@example.com', ['session-1']], [$redirect['name_id'], $redirect['session_indexes']]);
        self::assertStringStartsWith('_l', $redirect['id']);
        $post = $saml->consumeLogoutRequest($provider, $sp, $idp->logoutRequest($slo, 'ada@example.com', redirect: false), deflated: false);
        self::assertSame('ada@example.com', $post['name_id']);
        foreach (['unsigned redirect' => [$idp->logoutRequest($slo, 'ada@example.com', sign: false), true], 'unsigned post' => [$idp->logoutRequest($slo, 'ada@example.com', redirect: false, sign: false), false], 'another destination' => [$idp->logoutRequest('https://someone.else/slo', 'ada@example.com'), true], 'tampered' => [[...$idp->logoutRequest($slo, 'ada@example.com'), 'RelayState' => 'changed'], true]] as $name => [$message, $deflated]) {
            try {
                $saml->consumeLogoutRequest($provider, $sp, $message, $deflated);
                self::fail($name . ' was accepted');
            } catch (SsoException $exception) {
                self::assertSame(SsoException::ASSERTION_INVALID, $exception->reason, $name);
            }
        }

        $responseUrl = $saml->logoutResponseUrl($provider, $sp, $redirect['id'], 'rs');
        self::assertNotNull($responseUrl);
        self::assertStringStartsWith(TestIdp::SLO_URL . '?SAMLResponse=', $responseUrl);
        self::assertStringContainsString('&RelayState=rs', $responseUrl);
        $logoutUrl = $saml->logoutUrl($provider, $sp, 'ada@example.com', 'session-1', 'rs');
        self::assertNotNull($logoutUrl);
        self::assertStringStartsWith(TestIdp::SLO_URL . '?SAMLRequest=', $logoutUrl);
        $noSlo = self::provider(Provider::SAML, ['sso_url' => TestIdp::SSO_URL, 'certificate' => $idp->certificateBody()], issuer: TestIdp::ENTITY_ID);
        self::assertNull($saml->logoutUrl($noSlo, $sp, 'ada@example.com', null, 'rs'));
        self::assertNull($saml->logoutResponseUrl($noSlo, $sp, 'x', null));
    }

    public function testTheDomainVerifierChecksDnsThenTheWellKnownFile(): void
    {
        $client = new RoutingHttpClient(['https://acme.example/.well-known/polaris-sso.txt' => "polaris-sso-token\n"]);
        $verifier = new DnsHttpsDomainVerifier($client, new RequestFactory(), static fn(string $name): array => $name === '_polaris.dns.example' ? ['polaris-sso-token'] : []);

        self::assertSame('dns', $verifier->verify('dns.example', 'polaris-sso-token'));
        self::assertSame('https', $verifier->verify('acme.example', 'polaris-sso-token'));
        self::assertNull($verifier->verify('acme.example', 'other-token'));
        self::assertNull($verifier->verify('nowhere.example', 'polaris-sso-token'));
        self::assertNull((new DnsHttpsDomainVerifier(null, null, static fn(string $name): array => []))->verify('acme.example', 'polaris-sso-token'), 'no client, no HTTPS check');
        self::assertTrue(str_contains((string) $client->requests[0]->getUri(), 'acme.example'));
    }

    /**
     * @param array<string, mixed> $config
     * @param array<string, string> $attributes
     */
    private static function provider(string $type, array $config, string $issuer = self::ISSUER, array $attributes = []): Provider
    {
        $provider = new Provider();
        $provider->id = 'p1';
        $provider->organizationId = 'org-1';
        $provider->type = $type;
        $provider->name = 'Test';
        $provider->issuer = $issuer;
        $provider->config = json_encode($config, JSON_THROW_ON_ERROR);
        $provider->attributes = json_encode($attributes, JSON_THROW_ON_ERROR);
        $provider->redirectUris = json_encode(['https://app.example/done'], JSON_THROW_ON_ERROR);
        $provider->createdAt = $provider->updatedAt = new DateTimeImmutable('2026-09-11T10:00:00+00:00');

        return $provider;
    }
}

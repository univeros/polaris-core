<?php

declare(strict_types=1);

namespace Polaris\OAuth\Tests;

use DateTimeImmutable;
use Laminas\Diactoros\RequestFactory;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Exception\InvalidTokenException;
use Polaris\Model\User;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Authorization;
use Polaris\OAuth\Ciba;
use Polaris\OAuth\ClientCredentials;
use Polaris\OAuth\Clients;
use Polaris\OAuth\CodeReused;
use Polaris\OAuth\Codes;
use Polaris\OAuth\Consents;
use Polaris\OAuth\Devices;
use Polaris\OAuth\Discovery;
use Polaris\OAuth\Dpop;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\Exchange;
use Polaris\OAuth\Fetch;
use Polaris\OAuth\Http\OAuthRequestMiddleware;
use Polaris\OAuth\IssuedClient;
use Polaris\OAuth\Jwt;
use Polaris\OAuth\Model\Client;
use Polaris\OAuth\Model\Token;
use Polaris\OAuth\OAuthException;
use Polaris\OAuth\OAuthPlugin;
use Polaris\OAuth\OAuthResolver;
use Polaris\OAuth\PendingRequest;
use Polaris\OAuth\Schema;
use Polaris\OAuth\Scopes;
use Polaris\OAuth\Settings;
use Polaris\OAuth\Tests\Support\FakeHttp;
use Polaris\OAuth\Tests\Support\Keys;
use Polaris\OAuth\Tokens;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function array_keys;
use function array_unshift;
use function base64_encode;
use function explode;
use function json_decode;
use function str_repeat;

/**
 * The plugin wired through `Polaris::create()`, and the services on their own: the settings, the JWK
 * thumbprint (RFC 7638's vector), DPoP freshness and replay, the metadata URL rules, scopes, PKCE,
 * the token family, the device and backchannel throttles with a mutable clock, discovery, the
 * listeners. Separate processes: the schema registry is static.
 */
#[CoversClass(OAuthPlugin::class)]
#[CoversClass(Settings::class)]
#[CoversClass(Schema::class)]
#[CoversClass(Jwt::class)]
#[CoversClass(Dpop::class)]
#[CoversClass(Fetch::class)]
#[CoversClass(Scopes::class)]
#[CoversClass(Clients::class)]
#[CoversClass(ClientCredentials::class)]
#[CoversClass(IssuedClient::class)]
#[CoversClass(Consents::class)]
#[CoversClass(Codes::class)]
#[CoversClass(Tokens::class)]
#[CoversClass(Authorization::class)]
#[CoversClass(PendingRequest::class)]
#[CoversClass(Devices::class)]
#[CoversClass(Ciba::class)]
#[CoversClass(Exchange::class)]
#[CoversClass(Discovery::class)]
#[CoversClass(OAuthResolver::class)]
#[CoversClass(OAuthRequestMiddleware::class)]
#[CoversClass(OAuthEvent::class)]
#[CoversClass(OAuthException::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-10T10:00:00+00:00';
    private const string BASE = 'https://auth.polaris.test';

    private MutableClock $clock;
    private RecordingEventDispatcher $events;
    private FakeHttp $http;

    protected function setUp(): void
    {
        $this->clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $this->events = new RecordingEventDispatcher();
        $this->http = new FakeHttp();
    }

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();
        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[] = $model->table;
        }
        foreach ([Schema::CLIENTS, Schema::CONSENTS, Schema::CODES, Schema::TOKENS, Schema::DEVICE_CODES, Schema::CIBA_REQUESTS] as $table) {
            self::assertContains($table, $tables);
        }
        $routes = 0;
        foreach ($graph->manifest()->endpoints() as $spec) {
            if ($spec->plugin === OAuthPlugin::ID) {
                ++$routes;
                $graph->endpoint($spec->class);
            }
        }
        self::assertSame(26, $routes);
        self::assertInstanceOf(OAuthResolver::class, $graph->bearerResolvers()[0]);
        self::assertInstanceOf(OAuthRequestMiddleware::class, OAuthPlugin::of($graph)->middleware($graph)[0]);
        $polaris->listeners();
        self::assertTrue($graph->get(Catalog::class)->has(AuditNames::TOKEN_ISSUED));
        self::assertSame(self::BASE, OAuthPlugin::of($graph)->baseUrl());
    }

    public function testTheSettingsAreValidated(): void
    {
        $this->expectException(LogicException::class);
        new Settings(consentUrl: 'not a url');
    }

    public function testTheSettingsRefuseAnUnknownDpopMode(): void
    {
        $this->expectException(LogicException::class);
        new Settings(dpop: 'maybe');
    }

    public function testTheThumbprintMatchesRfc7638AndTheHeaderIsReadWithoutVerifying(): void
    {
        $jwk = ['kty' => 'RSA', 'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw', 'e' => 'AQAB', 'alg' => 'RS256', 'kid' => '2011-04-29'];
        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', Jwt::thumbprint($jwk));
        $graph = $this->polaris()->graph();
        $jwt = $graph->get(Jwt::class);
        $minted = $jwt->mint(['sub' => 'u1', 'jti' => 'j1', 'aud' => [self::BASE, 'https://api.test'], 'scope' => 'org.read'], $this->clock->now()->modify('+1 hour'), ['typ' => 'at+jwt']);
        self::assertSame('at+jwt', Jwt::header($minted)['typ'] ?? null);
        self::assertNull(Jwt::header('not.a'));
        $verified = $jwt->verify($minted, 'at+jwt');
        self::assertSame(['u1', [self::BASE, 'https://api.test'], 'org.read', 'test'], [$verified['claims']['sub'], $verified['claims']['aud'], $verified['claims']['scope'], $verified['headers']['kid']]);
        $this->refused(static fn() => $jwt->verify($minted, 'JWT'), OAuthException::INVALID_TOKEN, 'wrong typ');
        // Core's session parser refuses what the provider signs with the same key: an access token (its typ) and an ID token (its audience).
        $idToken = $jwt->mint(['sub' => 'u1', 'jti' => 'j2', 'aud' => 'client-1'], $this->clock->now()->modify('+1 hour'));
        foreach ([$minted, $idToken] as $foreign) {
            try {
                $graph->tokenParser()->parse($foreign);
                self::fail('not a session');
            } catch (InvalidTokenException) {
                self::addToAssertionCount(1);
            }
        }
        $session = $graph->tokenGenerator()->generate(['sub' => 'u1', 'jti' => 'j3']);
        self::assertSame('u1', $graph->tokenParser()->parse($session)->getMetadata('sub'), 'a session still parses');
        $this->clock->advance('+2 hours');
        $this->refused(static fn() => $jwt->verify($minted), OAuthException::INVALID_TOKEN, 'expired');
    }

    public function testADpopProofIsFreshBoundAndUsedOnce(): void
    {
        $graph = $this->polaris()->graph();
        $dpop = $graph->get(Dpop::class);
        $keys = new Keys();
        $now = $this->clock->now()->getTimestamp();
        self::assertNull($dpop->verify(null, 'POST', self::BASE . '/oauth2/token'));
        self::assertSame($keys->dpopThumbprint(), $dpop->verify($keys->dpopProof('POST', self::BASE . '/oauth2/token?x=1', null, 'j1', $now), 'POST', self::BASE . '/oauth2/token', null));
        $this->refused(static fn() => $dpop->verify($keys->dpopProof('POST', self::BASE . '/oauth2/token', null, 'j1', $now), 'POST', self::BASE . '/oauth2/token'), OAuthException::INVALID_DPOP_PROOF, 'replayed jti');
        $this->refused(static fn() => $dpop->verify($keys->dpopProof('POST', self::BASE . '/oauth2/token', null, 'j2', $now - 1000), 'POST', self::BASE . '/oauth2/token'), OAuthException::INVALID_DPOP_PROOF, 'stale');
        $this->refused(static fn() => $dpop->verify($keys->dpopProof('GET', self::BASE . '/oauth2/token', null, 'j3', $now), 'POST', self::BASE . '/oauth2/token'), OAuthException::INVALID_DPOP_PROOF, 'another method');
        $this->refused(static fn() => $dpop->verify($keys->dpopProof('POST', self::BASE . '/x', 'tok', 'j4', $now), 'POST', self::BASE . '/x', 'other'), OAuthException::INVALID_DPOP_PROOF, 'another token');
        $this->refused(static fn() => $dpop->verify('garbage', 'POST', self::BASE . '/x'), OAuthException::INVALID_DPOP_PROOF);
    }

    public function testMetadataUrlsMustBePublicHttpsWithAPath(): void
    {
        foreach (['https://client.example.com/app', 'https://client.example.com:443/app/client.json', 'https://[2001:4860::8888]/a'] as $ok) {
            Clients::assertPublicHttpsUrl($ok);
        }
        foreach (['http://client.example/app', 'https://client.example', 'https://localhost/app', 'https://app.localhost/x', 'https://10.1.2.3/app', 'https://127.0.0.1/app', 'https://[::1]/app', 'https://[fd00::1]/app', 'https://169.254.1.1/app', 'https://192.168.0.5/app', 'https://box.local/app', 'https://svc.internal/app', 'https://foo.home.arpa/app', 'https://x.onion/app', 'https://a.test/app', 'https://client.example.com/app#frag', 'https://client.example/app', 'https://client.example.com:8443/app', 'https://localhost./app', 'https://2130706433/app', 'https://0x7f.1/app', 'https://user@client.example.com/app'] as $bad) {
            $this->refused(static fn() => Clients::assertPublicHttpsUrl($bad), OAuthException::INVALID_CLIENT_METADATA, $bad);
        }
        self::addToAssertionCount(3);
    }

    public function testScopesArePermissionsPlusTheOpenIdAndConfiguredOnes(): void
    {
        $graph = $this->polaris()->graph();
        $scopes = $graph->get(Scopes::class);
        self::assertSame(['openid', 'org.read', 'deploy'], $scopes->parse('openid org.read  deploy'));
        self::assertSame([], $scopes->parse(null));
        self::assertSame(['org.read'], $scopes->permissions(['openid', 'org.read', 'deploy']));
        $this->refused(static fn() => $scopes->parse('openid nothing'), OAuthException::INVALID_SCOPE);
        $client = new Client();
        $client->scopes = ['openid'];
        $this->refused(static fn() => $scopes->parse('org.read', $client), OAuthException::INVALID_SCOPE, 'beyond the client');
        self::assertSame(['org.read'], Scopes::within(['org.read'], ['org.read', 'openid']));
        $this->refused(static fn() => Scopes::within(['members.read'], ['org.read']), OAuthException::INVALID_SCOPE);
        self::assertContains('deploy', array_keys($scopes->all()));
    }

    public function testCodesTokensDevicesAndBackchannelRequestsExpireAndSpendOnce(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();
        $user = self::user($graph);
        $this->events->listen(...$polaris->listeners());
        $client = $graph->get(Clients::class)->create(['name' => 'CLI', 'redirect_uris' => ['https://cli.test/cb'], 'grant_types' => [Clients::GRANT_CODE, Clients::GRANT_REFRESH, Clients::GRANT_DEVICE, Clients::GRANT_CIBA]], null, null, true)->client;
        [$verifier, $challenge] = Keys::pkce();
        $codes = $graph->get(Codes::class);
        $code = $codes->issue($client, $user->id, null, ['org.read'], 'https://cli.test/cb', $challenge, 'n', null, null, null);
        $this->refused(static fn() => $codes->consume($code, $client, 'https://cli.test/other', $verifier), OAuthException::INVALID_GRANT, 'another redirect');
        $this->refused(static fn() => $codes->consume($code, $client, 'https://cli.test/cb', 'short'), OAuthException::INVALID_GRANT, 'bad verifier');
        $stored = $codes->consume($code, $client, 'https://cli.test/cb', $verifier);
        self::assertSame(['org.read'], $stored->scopes);
        try {
            $codes->consume($code, $client, 'https://cli.test/cb', $verifier);
            self::fail('spent');
        } catch (CodeReused $reused) {
            self::assertSame($stored->id, $reused->codeId, 'the replay names the code, so its family can be revoked');
        }
        $late = $codes->issue($client, $user->id, null, [], 'https://cli.test/cb', $challenge, null, null, null, null);
        $this->clock->advance('+11 minutes');
        $this->refused(static fn() => $codes->consume($late, $client, 'https://cli.test/cb', $verifier), OAuthException::INVALID_GRANT, 'expired');
        self::assertSame(2, $codes->prune());

        $tokens = $graph->get(Tokens::class);
        $issued = $tokens->issue($client, $user->id, null, ['org.read'], null, null);
        $record = $tokens->find(self::jti($issued['access_token']));
        self::assertInstanceOf(Token::class, $record);
        self::assertNotNull($record->familyId);
        $this->clock->advance('+2 hours');
        self::assertFalse($tokens->introspect($issued['access_token'])['active'], 'expired access token');
        $refreshed = $tokens->refresh($issued['refresh_token'], $client, null, ['org.read']);
        self::assertSame($record->familyId, $tokens->find(self::jti($refreshed['access_token']))?->familyId, 'the family continues');
        $this->clock->advance('+31 days');
        $this->refused(static fn() => $tokens->refresh($refreshed['refresh_token'], $client, null, null), OAuthException::INVALID_GRANT, 'expired refresh token');
        self::assertGreaterThan(0, $tokens->prune());

        $devices = $graph->get(Devices::class);
        $started = $devices->start($client, ['org.read'], null);
        $this->refused(static fn() => $devices->poll($started['device_code'], $client), OAuthException::AUTHORIZATION_PENDING);
        $this->refused(static fn() => $devices->poll($started['device_code'], $client), OAuthException::SLOW_DOWN, 'polled within the interval');
        $this->clock->advance('+6 seconds');
        $this->refused(static fn() => $devices->poll($started['device_code'], $client), OAuthException::AUTHORIZATION_PENDING);
        $this->clock->advance('+1 hour');
        $this->refused(static fn() => $devices->poll($started['device_code'], $client), OAuthException::EXPIRED_TOKEN);
        $this->refused(static fn() => $devices->byUserCode($started['user_code']), OAuthException::INVALID_GRANT, 'expired for the page too');
        self::assertSame(1, $devices->prune());

        $ciba = $graph->get(Ciba::class);
        [$response, $request] = $ciba->request($client, ['org.read'], 'ADA@example.com', 'Hi', null);
        self::assertSame($user->id, $request->userId, 'the hint is normalised');
        self::assertSame($response['auth_req_id'], $ciba->pending($user->id)[0]->id);
        $this->refused(static fn() => $ciba->poll($response['auth_req_id'], $client), OAuthException::AUTHORIZATION_PENDING);
        $this->refused(static fn() => $ciba->poll($response['auth_req_id'], $client), OAuthException::SLOW_DOWN);
        $this->refused(static fn() => $ciba->request($client, [], 'ada@example.com', str_repeat('x', 200), null), OAuthException::INVALID_REQUEST, 'binding message too long');
        $this->refused(static fn() => $ciba->decide('not-there', $user->id, true, null, null), OAuthException::NOT_FOUND);
        $ciba->decide($response['auth_req_id'], $user->id, false, null, null);
        $this->clock->advance('+6 seconds');
        $this->refused(static fn() => $ciba->poll($response['auth_req_id'], $client), OAuthException::ACCESS_DENIED);
        $this->clock->advance('+1 hour');
        self::assertSame(1, $ciba->prune());
    }

    public function testDiscoveryFollowsTheSettings(): void
    {
        $graph = $this->polaris(deviceUrl: null, dynamicRegistration: true, dpop: Settings::DPOP_OFF)->graph();
        $document = $graph->get(Discovery::class)->openId();
        self::assertArrayNotHasKey('device_authorization_endpoint', $document);
        self::assertArrayNotHasKey('dpop_signing_alg_values_supported', $document);
        self::assertSame(self::BASE . '/oauth2/register', $document['registration_endpoint']);
        self::assertNotContains(Clients::GRANT_DEVICE, $document['grant_types_supported']);
        self::assertSame(self::BASE . '/oauth2/userinfo', $document['userinfo_endpoint']);
        $this->refused(static fn() => $graph->get(Devices::class)->start(new Client(), [], null), OAuthException::UNAUTHORIZED_CLIENT, 'no deviceUrl');
    }

    public function testTheCredentialsAreReadFromTheBodyOrBasic(): void
    {
        $post = ClientCredentials::from(['client_id' => 'c', 'client_secret' => 's'], null);
        self::assertSame(['c', 's', false], [$post->clientId, $post->secret, $post->basic]);
        $basic = ClientCredentials::from([], 'Basic ' . base64_encode('c%3A1:s%2Fx'));
        self::assertSame(['c:1', 's/x', true], [$basic->clientId, $basic->secret, $basic->basic]);
        $assertion = ClientCredentials::from(['client_assertion' => 'a.b.c', 'client_assertion_type' => ClientCredentials::ASSERTION_TYPE], null);
        self::assertSame(['a.b.c', ClientCredentials::ASSERTION_TYPE, null], [$assertion->assertion, $assertion->assertionType, $assertion->clientId]);
    }

    public function testTheAuditPluginIsRequired(): void
    {
        $this->expectException(LogicException::class);
        $this->polaris(audit: false)->listeners();
    }

    private function polaris(bool $audit = true, ?string $deviceUrl = 'https://app.test/device', bool $dynamicRegistration = false, string $dpop = Settings::DPOP_OPTIONAL): Polaris
    {
        $keys = TestKeys::rsa();
        $plugins = [new AdminPlugin(), new OAuthPlugin(self::BASE, 'https://app.test/consent', $deviceUrl, $this->http, new RequestFactory(), dynamicRegistration: $dynamicRegistration, dpop: $dpop, scopes: ['deploy' => 'Deploy'])];
        if ($audit) {
            array_unshift($plugins, new AuditPlugin());
        }

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => self::BASE]),
            database: new InMemoryAdapter(),
            clock: $this->clock,
            dispatcher: $this->events,
            plugins: $plugins,
        ));
    }

    private static function user(Graph $graph): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = 'ada@example.com';
        $user->emailVerifiedAt = new DateTimeImmutable(self::NOW);
        $user->createdAt = new DateTimeImmutable(self::NOW);
        $user->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    private static function jti(string $jwt): string
    {
        $parts = explode('.', $jwt);
        $claims = (array) json_decode(Jwt::base64UrlDecode($parts[1] ?? ''), true);

        return (string) ($claims['jti'] ?? '');
    }

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, string $error, string $message = ''): void
    {
        try {
            $call();
            self::fail('refused: ' . $message);
        } catch (OAuthException $exception) {
            self::assertSame($error, $exception->error, $message . ' ' . $exception->description);
        }
    }
}

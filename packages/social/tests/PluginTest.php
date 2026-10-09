<?php

declare(strict_types=1);

namespace Polaris\Social\Tests;

use DateTimeImmutable;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\UserLoggedIn;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Social\Accounts;
use Polaris\Social\AuditNames;
use Polaris\Social\Event\SocialEvent;
use Polaris\Social\Model\Account;
use Polaris\Social\Provider\AppleProvider;
use Polaris\Social\Provider\Catalog as ProviderCatalog;
use Polaris\Social\Provider\GitHubProvider;
use Polaris\Social\Provider\Http;
use Polaris\Social\Provider\IdTokens;
use Polaris\Social\Provider\OAuth2Provider;
use Polaris\Social\Provider\Profile;
use Polaris\Social\Providers;
use Polaris\Social\Schema;
use Polaris\Social\Sessions;
use Polaris\Social\Settings;
use Polaris\Social\SocialException;
use Polaris\Social\SocialPlugin;
use Polaris\Social\SocialService;
use Polaris\Social\Tests\Support\RecordedProviders;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function array_filter;
use function array_map;
use function array_values;
use function explode;
use function in_array;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function parse_str;
use function parse_url;
use function str_contains;
use function str_repeat;
use function substr_count;

use const PHP_URL_QUERY;

/**
 * The plugin wired through `Polaris::create()` and the flows through the service against the recorded
 * providers: sign-up, sign-in, the linking policy, Apple's and Microsoft's id_tokens, One Tap offline,
 * provider tokens and their refresh, any other OAuth 2 server, and the OAuth proxy. Separate processes:
 * the schema registry is static.
 */
#[CoversClass(SocialPlugin::class)]
#[CoversClass(Settings::class)]
#[CoversClass(SocialService::class)]
#[CoversClass(Sessions::class)]
#[CoversClass(Accounts::class)]
#[CoversClass(Providers::class)]
#[CoversClass(ProviderCatalog::class)]
#[CoversClass(OAuth2Provider::class)]
#[CoversClass(AppleProvider::class)]
#[CoversClass(GitHubProvider::class)]
#[CoversClass(IdTokens::class)]
#[CoversClass(Http::class)]
#[CoversClass(SocialEvent::class)]
#[CoversClass(SocialException::class)]
#[CoversClass(Account::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-09T10:00:00+00:00';
    private const string BASE = 'https://app.example/auth';
    private const string DONE = 'https://app.example/signed-in';
    private const string PASSWORD = 'correct horse battery staple';

    private RecordedProviders $providers;
    private MutableClock $clock;
    private RecordingEventDispatcher $events;
    private ClientContext $client;

    protected function setUp(): void
    {
        $this->providers = new RecordedProviders();
        $this->clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $this->events = new RecordingEventDispatcher();
        $this->client = new ClientContext('203.0.113.7', 'ua/1');
        RecordedProviders::$nonce = null;
        RecordedProviders::$claims = [];
    }

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();

        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[] = $model->table;
        }
        self::assertContains(Schema::ACCOUNTS, $tables);
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (in_array('social', $spec->tags, true)) {
                $graph->endpoint($spec->class);
                $routes[] = $spec->method . ' ' . $spec->path . ' ' . $spec->auth . ($spec->stepUp ? ' step_up' : '');
            }
        }
        self::assertEqualsCanonicalizing(['POST /social/{provider}/start public', 'GET /social/{provider}/callback public', 'POST /social/{provider}/callback public', 'POST /social/exchange public', 'POST /social/google/one-tap public', 'GET /social/accounts bearer', 'POST /social/{provider}/link bearer step_up', 'DELETE /social/{provider} bearer step_up', 'POST /social/{provider}/token bearer step_up'], $routes);
        $polaris->plugin(SocialPlugin::ID)->listeners($graph);
        foreach (AuditNames::ALL as $name => $description) {
            self::assertTrue($graph->get(Catalog::class)->has($name), $name);
        }
        self::assertSame(self::BASE . '/social/google/callback', SocialPlugin::of($graph)->settings()->callbackUrl('google'));

        $registry = $graph->get(Providers::class);
        self::assertInstanceOf(AppleProvider::class, $registry->get('apple'));
        self::assertInstanceOf(GitHubProvider::class, $registry->get('github'));
        self::assertSame($registry->get('google'), $registry->get('google'), 'built once');
        $this->refused(fn() => $registry->get('nope'), SocialException::PROVIDER_NOT_FOUND);
        foreach (ProviderCatalog::IDS as $id) {
            $definition = ProviderCatalog::definition($id);
            $provider = new OAuth2Provider($definition, 'client-' . $id, 'secret', $graph->get(Http::class), new IdTokens($graph->get(Http::class), $graph->cache()));
            $url = $provider->authorizationUrl('https://app.example/cb', 'st4te', [], $definition->pkce ? 'ch4llenge' : null, 'n0nce');
            self::assertStringStartsWith($definition->authorizationEndpoint, $url, $id);
            self::assertStringContainsString($definition->clientIdParam . '=client-' . $id, $url, $id);
            self::assertStringContainsString('state=st4te', $url, $id);
            self::assertSame($definition->oidc(), str_contains($url, 'nonce=n0nce'), $id . ' sends a nonce when it is OpenID Connect');
            self::assertSame($definition->pkce, str_contains($url, 'code_challenge=ch4llenge'), $id . ' sends the PKCE challenge when it does PKCE');
            self::assertInstanceOf(Profile::class, ($definition->profile)(['sub' => 'x', 'id' => 'x', 'data' => ['id' => 'x', 'user' => []], 'owner' => []]), $id . ' maps an empty profile');
        }
        self::assertStringContainsString('response_mode=form_post', (new OAuth2Provider(ProviderCatalog::definition('apple'), 'c', null, $graph->get(Http::class), new IdTokens($graph->get(Http::class), $graph->cache())))->authorizationUrl('https://app.example/cb', 's', [], null, 'n'));
        self::assertMatchesRegularExpression('#^\#.*\#$#', (string) ProviderCatalog::definition('microsoft')->issuer, 'a common tenant accepts every tenant\'s issuer');
        self::assertSame('https://login.microsoftonline.com/contoso/v2.0', ProviderCatalog::definition('microsoft', ['tenant' => 'contoso'])->issuer);

        foreach ([static fn() => new Settings('/auth'), static fn() => new Settings(self::BASE, proxy: 'auth.example')] as $invalid) {
            try {
                $invalid();
                self::fail('the settings are validated');
            } catch (LogicException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testGoogleSignsUpSignsInAndLinksAnExistingUserBecauseItIsTrusted(): void
    {
        $graph = $this->polaris()->graph();
        $service = $graph->get(SocialService::class);

        $this->refused(fn() => $service->start('google', 'https://evil.example/', [], null), SocialException::REDIRECT_NOT_ALLOWED);
        $started = $service->start('google', null, [], null);
        self::assertStringStartsWith('https://accounts.google.com/o/oauth2/v2/auth?client_id=google-client&redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fsocial%2Fgoogle%2Fcallback', $started['url']);
        self::assertStringContainsString('code_challenge_method=S256', $started['url']);
        $this->refused(fn() => $service->callback('google', ['code' => 'good', 'state' => 'unknown'], $this->client), SocialException::STATE_INVALID);
        $this->refused(fn() => $service->callback('github', ['code' => 'good', 'state' => $started['state']], $this->client), SocialException::STATE_INVALID, 'another provider\'s state');
        $started = $this->restart($service, 'google');
        $this->refused(fn() => $service->callback('google', ['error' => 'access_denied', 'state' => $started['state']], $this->client), SocialException::PROVIDER_ERROR);
        $started = $this->restart($service, 'google');
        $redirect = $service->callback('google', ['code' => 'good', 'state' => $started['state']], $this->client);
        self::assertStringStartsWith(self::DONE . '?code=', $redirect);
        self::assertStringEndsWith('&state=' . $started['state'], $redirect, 'the application checks it started this flow');
        $form = RecordedProviders::form($this->providers->http->requests[0]);
        self::assertSame(['authorization_code', 'good', self::BASE . '/social/google/callback', 'google-client', 'google-secret'], [$form['grant_type'], $form['code'], $form['redirect_uri'], $form['client_id'], $form['client_secret']]);
        self::assertArrayHasKey('code_verifier', $form);
        $data = $service->exchange($this->code($redirect));
        $this->refused(fn() => $service->exchange($this->code($redirect)), SocialException::CODE_INVALID, 'once');
        self::assertSame(['Bearer', 'ada@example.com', true], [$data['token_type'], $data['user']['email'], $data['user']['email_verified']]);
        self::assertSame(['social:google'], $graph->tokenFactory()->fromTokenString((string) $data['access_token'])->getMetadata('amr'));
        $ada = $graph->users()->findOneBy(['email' => 'ada@example.com']);
        self::assertInstanceOf(User::class, $ada, 'signed up');
        self::assertSame(['Ada Lovelace', null, true], [$ada->displayName, $ada->passwordHash, $ada->emailVerifiedAt !== null]);
        $accounts = $service->accounts($ada->id);
        self::assertCount(1, $accounts);
        self::assertSame(['google', RecordedProviders::GOOGLE_SUB, 'ada@example.com', true, 'Ada Lovelace'], [$accounts[0]->provider, $accounts[0]->providerAccountId, $accounts[0]->email, $accounts[0]->emailVerified, $accounts[0]->profile['name']]);
        self::assertStringNotContainsString('ya29', (string) $accounts[0]->accessTokenEnc, 'encrypted at rest');
        self::assertSame('ya29.a0AfB_byC-recorded-google-access-token', $graph->get(Accounts::class)->accessToken($accounts[0]));
        self::assertSame([AuditNames::SIGNED_UP], $this->auditNames($graph, [AuditNames::SIGNED_UP, AuditNames::SIGNED_IN]));
        self::assertSame(['social:google'], $this->events->ofType(UserLoggedIn::class)[0]->amr);

        $again = $service->exchange($this->code($service->callback('google', ['code' => 'good', 'state' => $this->restart($service, 'google')['state']], $this->client)));
        self::assertSame($ada->id, $again['user']['id'], 'signed in by the linked account');
        self::assertCount(1, $graph->users()->findBy(['email' => 'ada@example.com']));
        self::assertSame([AuditNames::SIGNED_IN], $this->auditNames($graph, [AuditNames::SIGNED_IN]));

        $grace = $this->user($graph, 'grace@example.com');
        $this->providers->on('https://openidconnect.googleapis.com/v1/userinfo', ['sub' => 'g-grace', 'email' => 'grace@example.com', 'email_verified' => true, 'name' => 'Grace']);
        RecordedProviders::$claims['google'] = ['sub' => 'g-grace', 'email' => 'grace@example.com'];
        $linked = $service->exchange($this->code($service->callback('google', ['code' => 'good', 'state' => $this->restart($service, 'google')['state']], $this->client)));
        self::assertSame($grace->id, $linked['user']['id'], 'a trusted provider with a verified email links to the existing user');
        self::assertSame('google', $service->accounts($grace->id)[0]->provider);

        $bob = $this->user($graph, 'bob@example.com');
        $this->providers->on('https://openidconnect.googleapis.com/v1/userinfo', ['sub' => 'g-bob', 'email' => 'bob@example.com', 'email_verified' => false, 'name' => 'Bob']);
        RecordedProviders::$claims['google'] = ['sub' => 'g-bob', 'email' => 'bob@example.com', 'email_verified' => false];
        $this->refused(fn() => $service->callback('google', ['code' => 'good', 'state' => $this->restart($service, 'google')['state']], $this->client), SocialException::ACCOUNT_EXISTS, 'not verified: no link');
        self::assertSame([], $service->accounts($bob->id));

        $mallory = $this->user($graph, 'carol@example.com', verified: false);
        $stolen = $graph->tokens()->issue(new \Polaris\Token\SessionPrincipal($mallory->id), $this->client);
        $this->providers->on('https://openidconnect.googleapis.com/v1/userinfo', ['sub' => 'g-carol', 'email' => 'carol@example.com', 'email_verified' => true, 'name' => 'Carol']);
        RecordedProviders::$claims['google'] = ['sub' => 'g-carol', 'email' => 'carol@example.com', 'email_verified' => true];
        $claimed = $service->exchange($this->code($service->callback('google', ['code' => 'good', 'state' => $this->restart($service, 'google')['state']], $this->client)));
        self::assertSame($mallory->id, $claimed['user']['id'], 'the mailbox is proven now: the account is carol\'s');
        $graph->identities()->clear();
        $carol = $graph->users()->find($mallory->id);
        self::assertInstanceOf(User::class, $carol);
        self::assertSame([null, true], [$carol->passwordHash, $carol->emailVerifiedAt !== null], 'whoever registered the address without proving it lost the password');
        self::assertNull($graph->database()->findOne('auth_refresh_tokens', ['family_id' => $stolen->sessionId, 'revoked_at' => null]), 'and the sessions');

        $bob->status = User::STATUS_DISABLED;
        $graph->unitOfWork()->persist($bob);
        $graph->unitOfWork()->flush();
        RecordedProviders::$claims['google'] = ['sub' => 'g-bob', 'email' => 'bob@example.com', 'email_verified' => true];
        $this->providers->on('https://openidconnect.googleapis.com/v1/userinfo', ['sub' => 'g-bob', 'email' => 'bob@example.com', 'email_verified' => true, 'name' => 'Bob']);
        $this->refused(fn() => $service->callback('google', ['code' => 'good', 'state' => $this->restart($service, 'google')['state']], $this->client), SocialException::ACCOUNT_DISABLED);
    }

    public function testGitHubIsNotTrustedAndLinksFromASession(): void
    {
        $graph = $this->polaris(allowDifferentEmails: [])->graph();
        $service = $graph->get(SocialService::class);
        $grace = $this->user($graph, 'grace@example.com');

        $this->refused(fn() => $service->callback('github', ['code' => 'good', 'state' => $this->restart($service, 'github')['state']], $this->client), SocialException::ACCOUNT_EXISTS, 'the email exists; GitHub is not trusted to link it');
        self::assertSame([AuditNames::REJECTED], $this->auditNames($graph, [AuditNames::REJECTED]));

        $started = $service->start('github', null, [], $grace->id);
        self::assertStringNotContainsString('code_challenge', $started['url'], 'GitHub does no PKCE');
        $outcome = $service->exchange($this->code($service->callback('github', ['code' => 'good', 'state' => $started['state']], $this->client)));
        self::assertSame(['linked', 'github', '583231', 'grace@example.com', true], [$outcome['status'], $outcome['account']['provider'], $outcome['account']['provider_account_id'], $outcome['account']['email'], $outcome['account']['email_verified']], 'the verified primary email from /user/emails');
        self::assertSame('Grace Hopper', $outcome['account']['profile']['name']);
        $token = $service->token($grace->id, 'github');
        self::assertSame(['gho_recordedGitHubAccessToken0123456789', null, ['read:user', 'user:email']], [$token['access_token'], $token['expires_at'], $token['scopes']]);

        $signedIn = $service->exchange($this->code($service->callback('github', ['code' => 'good', 'state' => $this->restart($service, 'github')['state']], $this->client)));
        self::assertSame($grace->id, $signedIn['user']['id'], 'linked: it signs in now');

        $bob = $this->user($graph, 'bob@example.com');
        $this->refused(fn() => $service->callback('github', ['code' => 'good', 'state' => $service->start('github', null, [], $bob->id)['state']], $this->client), SocialException::ACCOUNT_LINKED, 'grace\'s GitHub account');
        $this->providers->on('https://api.github.com/user', ['id' => 999, 'login' => 'bobby', 'email' => null]);
        $this->providers->on('https://api.github.com/user/emails', [['email' => 'bobby@elsewhere.example', 'primary' => true, 'verified' => true]]);
        $this->refused(fn() => $service->callback('github', ['code' => 'good', 'state' => $service->start('github', null, [], $bob->id)['state']], $this->client), SocialException::EMAIL_MISMATCH);
        $graph = $this->polaris(allowDifferentEmails: ['github'])->graph();
        $service = $graph->get(SocialService::class);
        $bob = $this->user($graph, 'bob@example.com');
        self::assertSame('linked', $service->exchange($this->code($service->callback('github', ['code' => 'good', 'state' => $service->start('github', null, [], $bob->id)['state']], $this->client)))['status'], 'allowed for GitHub');

        $this->refused(fn() => $service->unlink($bob->id, 'google'), SocialException::NOT_LINKED);
        $service->unlink($bob->id, 'github');
        self::assertSame([], $service->accounts($bob->id));
        self::assertSame([AuditNames::UNLINKED], $this->auditNames($graph, [AuditNames::UNLINKED]));
    }

    public function testUnlinkingTheLastCredentialIsRefused(): void
    {
        $graph = $this->polaris()->graph();
        $service = $graph->get(SocialService::class);
        $data = $service->exchange($this->code($service->callback('google', ['code' => 'good', 'state' => $this->restart($service, 'google')['state']], $this->client)));
        $adaId = (string) $data['user']['id'];

        $this->refused(fn() => $service->unlink($adaId, 'google'), SocialException::LAST_CREDENTIAL, 'no password, one provider');
        self::assertSame('linked', $service->exchange($this->code($service->callback('github', ['code' => 'good', 'state' => $service->start('github', null, [], $adaId)['state']], $this->client)))['status'], 'GitHub reports grace@, allowed here as ada links from her session with allowDifferentEmails');
        $service->unlink($adaId, 'google');
        self::assertSame(['github'], array_map(static fn(Account $account): string => $account->provider, $service->accounts($adaId)));
    }

    public function testAppleAndMicrosoftReadTheIdToken(): void
    {
        $graph = $this->polaris()->graph();
        $service = $graph->get(SocialService::class);

        $started = $this->restart($service, 'apple');
        self::assertStringContainsString('response_mode=form_post', $started['url']);
        $data = $service->exchange($this->code($service->callback('apple', ['code' => 'good', 'state' => $started['state'], 'user' => '{"name":{"firstName":"Alan","lastName":"Turing"},"email":"alan@example.com"}'], $this->client)));
        $alan = $graph->users()->find($data['user']['id']);
        self::assertInstanceOf(User::class, $alan);
        self::assertSame(['alan@example.com', 'Alan Turing', true], [$alan->email, $alan->displayName, $alan->emailVerifiedAt !== null], 'the name from the first callback, the email from the id_token');
        $form = RecordedProviders::form($this->providers->http->requests[0]);
        $public = openssl_pkey_get_details((openssl_pkey_get_private(RecordedProviders::appleClientKey()) ?: throw new LogicException('key')))['key'];
        JWT::$timestamp = (new DateTimeImmutable(self::NOW))->getTimestamp();
        $secret = (array) JWT::decode($form['client_secret'], new Key($public, 'ES256'));
        JWT::$timestamp = null;
        self::assertSame(['TEAM123', 'com.example.app', 'https://appleid.apple.com'], [$secret['iss'], $secret['sub'], $secret['aud']], 'the client secret is a JWT under the team key');

        $data = $service->exchange($this->code($service->callback('microsoft', ['code' => 'good', 'state' => $this->restart($service, 'microsoft')['state']], $this->client)));
        self::assertSame('linus@example.com', $data['user']['email'], 'a tenant issuer under the common endpoint');

        RecordedProviders::$claims['microsoft'] = ['nonce' => 'stale'];
        $this->refused(fn() => $service->callback('microsoft', ['code' => 'good', 'state' => $this->restart($service, 'microsoft')['state']], $this->client), SocialException::PROVIDER_ERROR, 'a wrong nonce');
        RecordedProviders::$claims['microsoft'] = ['iss' => 'https://evil.example'];
        $this->refused(fn() => $service->callback('microsoft', ['code' => 'good', 'state' => $this->restart($service, 'microsoft')['state']], $this->client), SocialException::PROVIDER_ERROR, 'a wrong issuer');
        self::assertCount(2, $graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::REJECTED]))->events);
    }

    public function testOneTapVerifiesTheIdTokenOfflineAgainstTheRecordedKeys(): void
    {
        $graph = $this->polaris()->graph();
        $service = $graph->get(SocialService::class);

        $credential = RecordedProviders::mint('https://accounts.google.com', 'google-client', RecordedProviders::GOOGLE_SUB, 'ada@example.com', true, 'Ada Lovelace');
        $data = $service->idTokenSignIn('google', $credential, $this->client);
        self::assertSame(['ada@example.com', ['social:google']], [$data['user']['email'], $graph->tokenFactory()->fromTokenString((string) $data['access_token'])->getMetadata('amr')]);
        $urls = array_map(static fn($request): string => (string) $request->getUri(), $this->providers->http->requests);
        self::assertSame(['https://accounts.google.com/.well-known/openid-configuration', 'https://www.googleapis.com/oauth2/v3/certs'], $urls, 'discovery and the keys, nothing else');
        $this->providers->http->requests = [];
        $service->idTokenSignIn('google', RecordedProviders::mint('https://accounts.google.com', 'google-client', RecordedProviders::GOOGLE_SUB, 'ada@example.com', true, null), $this->client);
        self::assertSame([], $this->providers->http->requests, 'the keys are cached');
        $adaId = (string) $data['user']['id'];
        $this->refused(fn() => $service->token($adaId, 'google'), SocialException::NO_REFRESH, 'One Tap stores no provider token');
        $service->exchange($this->code($service->callback('google', ['code' => 'good', 'state' => $this->restart($service, 'google')['state']], $this->client)));
        $service->idTokenSignIn('google', RecordedProviders::mint('https://accounts.google.com', 'google-client', RecordedProviders::GOOGLE_SUB, 'ada@example.com', true, null), $this->client);
        self::assertSame('ya29.a0AfB_byC-recorded-google-access-token', $service->token($adaId, 'google')['access_token'], 'and does not clobber the one a callback stored');

        [$header, $payload, $signature] = explode('.', $credential);
        $this->refused(fn() => $service->idTokenSignIn('google', $header . '.' . $payload . '.' . substr($signature, 0, -4) . 'AAAA', $this->client), SocialException::PROVIDER_ERROR, 'tampered');
        $this->refused(fn() => $service->idTokenSignIn('google', RecordedProviders::mint('https://accounts.google.com', 'another-client', RecordedProviders::GOOGLE_SUB, 'ada@example.com', true, null), $this->client), SocialException::PROVIDER_ERROR, 'another audience');
        $this->refused(fn() => $service->idTokenSignIn('github', $credential, $this->client), SocialException::INVALID_INPUT, 'not OpenID Connect');
    }

    public function testProviderTokensRefreshWhenExpiringAndAnyOAuth2ServerWorksFromItsDefinitionOrDiscovery(): void
    {
        $graph = $this->polaris()->graph();
        $service = $graph->get(SocialService::class);
        $data = $service->exchange($this->code($service->callback('google', ['code' => 'good', 'state' => $this->restart($service, 'google')['state']], $this->client)));
        $adaId = (string) $data['user']['id'];
        $requests = count($this->providers->http->requests);

        $token = $service->token($adaId, 'google');
        self::assertSame(['ya29.a0AfB_byC-recorded-google-access-token', '2026-10-09T10:59:59+00:00'], [$token['access_token'], $token['expires_at']]);
        self::assertCount($requests, $this->providers->http->requests, 'still valid: no call');
        $this->clock->advance('+59 minutes');
        $this->providers->on('https://oauth2.googleapis.com/token', ['access_token' => 'ya29.refreshed', 'expires_in' => 3599, 'scope' => 'openid email', 'token_type' => 'Bearer']);
        $refreshed = $service->token($adaId, 'google');
        self::assertSame(['ya29.refreshed', '2026-10-09T11:58:59+00:00'], [$refreshed['access_token'], $refreshed['expires_at']]);
        self::assertSame(['refresh_token', '1//0g-recorded-google-refresh-token'], [RecordedProviders::form($this->providers->http->requests[$requests])['grant_type'], RecordedProviders::form($this->providers->http->requests[$requests])['refresh_token']]);
        self::assertSame([AuditNames::TOKEN_REFRESHED], $this->auditNames($graph, [AuditNames::TOKEN_REFRESHED]));
        $this->refused(fn() => $service->token($adaId, 'github'), SocialException::NOT_LINKED);

        $this->providers->on('https://acme.example/oauth/me', ['id' => 'acme-43', 'email' => 'zoe@example.com', 'verified' => false, 'name' => 'Zoe']);
        $this->refused(fn() => $service->callback('acme', ['code' => 'good', 'state' => $this->restart($service, 'acme')['state']], $this->client), SocialException::EMAIL_UNVERIFIED, 'signed up unverified: core requires a verified email to sign in');
        self::assertInstanceOf(User::class, $graph->users()->findOneBy(['email' => 'zoe@example.com']), 'the account exists, to verify');
        $this->providers->on('https://acme.example/oauth/me', ['id' => 'acme-42', 'email' => 'eve@example.com', 'verified' => true, 'name' => 'Eve']);
        $eve = $service->exchange($this->code($service->callback('acme', ['code' => 'good', 'state' => $this->restart($service, 'acme')['state']], $this->client)));
        self::assertSame(['eve@example.com', ['social:acme']], [$eve['user']['email'], $graph->tokenFactory()->fromTokenString((string) $eve['access_token'])->getMetadata('amr')], 'GenericOAuth from a definition');
        $this->events->dispatch(new \Polaris\Event\UserDeleted((string) $eve['user']['id'], 'admin'));
        self::assertSame([], $service->accounts((string) $eve['user']['id']), 'an erased user leaves no provider account');
        $started = $this->restart($service, 'okta');
        self::assertStringStartsWith('https://acme.okta.example/oauth2/v1/authorize?', $started['url'], 'discovered');
        $frank = $service->exchange($this->code($service->callback('okta', ['code' => 'good', 'state' => $started['state']], $this->client)));
        self::assertSame('frank@example.com', $frank['user']['email']);
    }

    public function testTheProxyForwardsASignedStateAndRefusesAnUnsignedOne(): void
    {
        $preview = $this->polaris(baseUrl: 'https://pr-42.preview.example/auth', proxy: 'https://auth.example')->graph();
        $stable = $this->polaris(baseUrl: 'https://auth.example/auth', proxy: 'https://auth.example')->graph();
        $previewService = $preview->get(SocialService::class);
        $stableService = $stable->get(SocialService::class);

        $started = $previewService->start('google', null, [], null);
        self::assertStringContainsString('redirect_uri=https%3A%2F%2Fauth.example%2Fsocial%2Fgoogle%2Fcallback', $started['url'], 'the provider sends the browser to the stable origin');
        self::assertSame(2, substr_count($started['state'], '.'), 'the state carries the signed return_to');
        $forward = $stableService->callback('google', ['code' => 'good', 'state' => $started['state']], $this->client);
        self::assertSame('https://pr-42.preview.example/auth/social/google/callback?code=good&state=' . rawurlencode($started['state']), $forward, 'forwarded with everything the provider sent');

        [$random, $payload, $signature] = explode('.', $started['state']);
        $forged = rtrim(strtr(base64_encode('{"return_to":"https://evil.example/social/google/callback"}'), '+/', '-_'), '=');
        $this->refused(fn() => $stableService->callback('google', ['code' => 'good', 'state' => $random . '.' . $forged . '.' . $signature], $this->client), SocialException::STATE_INVALID, 'a tampered return_to');
        $this->refused(fn() => $stableService->callback('google', ['code' => 'good', 'state' => $random . '.' . $payload . '.unsigned'], $this->client), SocialException::STATE_INVALID, 'unsigned');
        $this->refused(fn() => $stableService->callback('google', ['code' => 'good', 'state' => $random], $this->client), SocialException::STATE_INVALID, 'a plain state the stable origin never issued');
        $this->refused(fn() => $stableService->callback('github', ['code' => 'good', 'state' => $started['state']], $this->client), SocialException::STATE_INVALID, 'signed for another provider');
        $this->clock->advance('+11 minutes');
        $this->refused(fn() => $stableService->callback('google', ['code' => 'good', 'state' => $started['state']], $this->client), SocialException::STATE_INVALID, 'expired with the state');
        $this->clock->advance('-11 minutes');

        RecordedProviders::$nonce = RecordedProviders::param($started['url'], 'nonce');
        $redirect = $previewService->callback('google', ['code' => 'good', 'state' => $started['state']], $this->client);
        self::assertStringStartsWith(self::DONE . '?code=', $redirect, 'the preview completes its own flow');
        $exchanges = array_values(array_filter($this->providers->http->requests, static fn($request): bool => str_contains((string) $request->getBody(), 'grant_type=authorization_code')));
        self::assertSame('https://auth.example/social/google/callback', RecordedProviders::form($exchanges[0])['redirect_uri'], 'the exchange names the redirect_uri the provider saw');
        self::assertSame('ada@example.com', $previewService->exchange($this->code($redirect))['user']['email']);

        $own = $stableService->start('google', null, [], null);
        self::assertStringNotContainsString('.', $own['state'], 'the stable origin signs nothing for itself');
    }

    /**
     * @return array{url: string, state: string}
     */
    private function restart(SocialService $service, string $provider): array
    {
        $started = $service->start($provider, null, [], null);
        RecordedProviders::$nonce = RecordedProviders::param($started['url'], 'nonce');

        return $started;
    }

    private function code(string $redirect): string
    {
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);

        return (string) ($query['code'] ?? '');
    }

    /**
     * @param list<string> $names
     * @return list<string>
     */
    private function auditNames(Graph $graph, array $names): array
    {
        $found = [];
        foreach ($graph->get(Store::class)->read(new AuditQuery(names: $names))->events as $event) {
            $found[] = $event->name;
        }

        return $found;
    }

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, string $reason, string $message = ''): void
    {
        try {
            $call();
            self::fail($message === '' ? 'expected ' . $reason : $message);
        } catch (SocialException $exception) {
            self::assertSame($reason, $exception->reason, $message . ' (' . $exception->detail . ')');
        }
    }

    private function user(Graph $graph, string $email, bool $verified = true): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->passwordHash = $graph->passwordHasher()->hash(self::PASSWORD);
        $user->emailVerifiedAt = $verified ? $this->clock->now() : null;
        $user->createdAt = $user->updatedAt = $this->clock->now();
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    /**
     * @param list<string> $allowDifferentEmails
     */
    private function polaris(string $baseUrl = self::BASE, ?string $proxy = null, array $allowDifferentEmails = ['github']): Polaris
    {
        $keys = TestKeys::rsa();

        $polaris = Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: $this->clock,
            dispatcher: $this->events,
            plugins: [new AuditPlugin(), new SocialPlugin(
                $baseUrl,
                [
                    'google' => ['client_id' => 'google-client', 'client_secret' => 'google-secret'],
                    'github' => ['client_id' => 'github-client', 'client_secret' => 'github-secret'],
                    'apple' => ['client_id' => 'com.example.app', 'team_id' => 'TEAM123', 'key_id' => 'KEY123', 'private_key' => RecordedProviders::appleClientKey()],
                    'microsoft' => ['client_id' => 'ms-client', 'client_secret' => 'ms-secret', 'tenant' => 'common'],
                    'acme' => ['client_id' => 'acme-client', 'client_secret' => 'acme-secret', 'definition' => RecordedProviders::acme()],
                    'okta' => ['client_id' => 'okta-client', 'client_secret' => 'okta-secret', 'issuer' => 'https://acme.okta.example'],
                ],
                $this->providers->http,
                new RequestFactory(),
                new StreamFactory(),
                redirectUris: [self::DONE],
                allowDifferentEmails: $allowDifferentEmails,
                proxy: $proxy,
            )],
        ));
        $this->events->listen(...$polaris->listeners());

        return $polaris;
    }
}

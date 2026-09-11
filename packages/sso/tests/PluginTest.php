<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\MemberJoined;
use Polaris\Event\UserLoggedIn;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Schema\Schema as CoreSchema;
use Polaris\Sso\AuditNames;
use Polaris\Sso\Domains;
use Polaris\Sso\Http\Organization\ProviderInput;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Providers;
use Polaris\Sso\Provisioner;
use Polaris\Sso\Schema;
use Polaris\Sso\Sp;
use Polaris\Sso\SsoAudit;
use Polaris\Sso\SsoException;
use Polaris\Sso\SsoPlugin;
use Polaris\Sso\SsoService;
use Polaris\Sso\Tests\Support\FakeOidc;
use Polaris\Sso\Tests\Support\FakeSaml;
use Polaris\Sso\Tests\Support\FakeVerifier;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Wiring\Config;

use function in_array;
use function parse_str;
use function parse_url;
use function sort;
use function str_contains;

use const PHP_URL_QUERY;

/**
 * The plugin wired through `Polaris::create()` and the sign-in flow through the service with the fake
 * protocols: routing, state, provisioning, memberships, sessions, the hand-off code, replay, single
 * logout, the audit trail. Separate processes: the schema registry is static.
 */
#[CoversClass(SsoPlugin::class)]
#[CoversClass(SsoService::class)]
#[CoversClass(Provisioner::class)]
#[CoversClass(Providers::class)]
#[CoversClass(Domains::class)]
#[CoversClass(SsoAudit::class)]
#[CoversClass(ProviderInput::class)]
#[CoversClass(Provider::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-09-11T10:00:00+00:00';
    private const string BASE = 'https://app.example/auth';

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = self::polaris();
        $graph = $polaris->graph();

        self::assertCount(22, $polaris->schema(), 'core, audit, admin and the two sso tables');
        self::assertSame(Schema::PROVIDERS, CoreSchema::for(Provider::class)->table);
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (!in_array('sso', $spec->tags, true)) {
                continue;
            }
            $graph->endpoint($spec->class);
            $routes[] = $spec->method . ' ' . $spec->path;
            if (str_starts_with($spec->path, '/orgs/')) {
                self::assertSame(['bearer', ['org.update']], [$spec->auth, $spec->requiresPermissions], $spec->file);
            } elseif (str_starts_with($spec->path, '/admin/')) {
                self::assertSame('public', $spec->auth, $spec->file);
                self::assertContains('admin', $spec->tags, $spec->file);
            }
        }
        sort($routes);
        self::assertCount(20, $routes);
        self::assertContains('POST /sso/sign-in', $routes);
        self::assertContains('GET /sso/callback/{providerId}', $routes);
        self::assertContains('POST /sso/callback/{providerId}', $routes);
        self::assertContains('DELETE /admin/sso/providers/{id}', $routes);
        $polaris->plugin(SsoPlugin::ID)->listeners($graph);
        foreach (AuditNames::ALL as $name => $description) {
            self::assertTrue($graph->get(Catalog::class)->has($name), $name);
        }
        $sp = $graph->get(Sp::class);
        self::assertSame([self::BASE . '/sso/metadata/p1', self::BASE . '/sso/callback/p1', self::BASE . '/sso/slo/p1'], [$sp->entityId('p1'), $sp->acsUrl('p1'), $sp->sloUrl('p1')]);
        self::assertSame(SsoPlugin::ID, SsoPlugin::of($graph)->id());
    }

    public function testProvidersKeepTheSecretEncryptedAndTheInputIsValidated(): void
    {
        $graph = self::polaris()->graph();
        $providers = $graph->get(Providers::class);

        $provider = $providers->create('org-1', Provider::OIDC, 'Okta', 'https://acme.okta.com', ['client_id' => 'c1', 'client_secret' => 'shh'], ['email' => 'email'], ['enabled' => true, 'roles' => ['member']], ['https://app.example/done'], true, 'u1');
        self::assertStringNotContainsString('shh', $provider->config, 'encrypted at rest');
        self::assertSame('shh', $providers->secret($provider));
        self::assertArrayNotHasKey('client_secret', $provider->toArray()['config']);
        self::assertTrue($provider->toArray()['config']['client_secret_set']);
        $providers->update($provider, 'Okta 2', $provider->issuer, ['client_id' => 'c1'], [], ['enabled' => false, 'roles' => []], ['https://app.example/done'], false);
        self::assertSame('shh', $providers->secret($providers->find($provider->id) ?? $provider), 'an update without a secret keeps it');
        $providers->update($provider, 'Okta 3', $provider->issuer, ['client_id' => 'c1', 'client_secret' => 'new'], [], ['enabled' => false, 'roles' => []], ['https://app.example/done'], true);
        self::assertSame('new', $providers->secret($provider));
        self::assertSame(['Okta 3', false, []], [$provider->name, $provider->jitEnabled(), $provider->jitRoles()]);
        self::assertNull($providers->secret($providers->create('org-1', Provider::SAML, 'IdP', 'https://idp', ['sso_url' => 'https://idp/sso', 'certificate' => 'x'], [], ['enabled' => false, 'roles' => []], ['https://app.example/done'], true, null)));
        self::assertCount(2, $providers->forOrganization('org-1'));
        $page = $providers->list(limit: 1);
        self::assertCount(1, $page['data']);
        self::assertNotNull($page['next_cursor']);
        self::assertCount(1, $providers->list(cursor: $page['next_cursor'])['data']);
        self::assertTrue($providers->delete($provider->id));
        self::assertFalse($providers->delete($provider->id));

        self::assertSame(['type must be saml or oidc.'], ProviderInput::from(['type' => 'ldap']));
        $errors = ProviderInput::from(['type' => 'saml', 'name' => '', 'issuer' => '', 'config' => ['sso_url' => 'nope', 'idp_initiated' => 'yes'], 'redirect_uris' => ['ftp://x'], 'enabled' => 'no']);
        self::assertIsArray($errors);
        self::assertCount(7, $errors);
        $errors = ProviderInput::from(['type' => 'oidc', 'name' => 'x', 'issuer' => 'https://idp', 'config' => [], 'redirect_uris' => []]);
        self::assertSame(['config.client_id is required.', 'redirect_uris needs at least one URL the sign-in may end on.'], $errors);
        $input = ProviderInput::from(['type' => 'oidc', 'name' => ' Okta ', 'issuer' => 'https://idp', 'config' => ['client_id' => 'c', 'unknown' => 'dropped'], 'jit' => ['enabled' => true, 'roles' => ['member', 'ops']], 'redirect_uris' => ['https://app.example/done'], 'attributes' => ['email' => 'mail']]);
        self::assertInstanceOf(ProviderInput::class, $input);
        self::assertSame(['Okta', ['client_id' => 'c'], ['enabled' => true, 'roles' => ['member', 'ops']], ['email' => 'mail'], true], [$input->name, $input->config, $input->jit, $input->attributes, $input->enabled]);
        $patched = ProviderInput::from(['enabled' => false], $provider);
        self::assertInstanceOf(ProviderInput::class, $patched);
        self::assertSame(['Okta 3', false, ['https://app.example/done']], [$patched->name, $patched->enabled, $patched->redirectUris]);
    }

    public function testTheOidcFlowRoutesByDomainProvisionsAndHandsTheSessionOver(): void
    {
        $events = new RecordingEventDispatcher();
        $polaris = self::polaris($events);
        $graph = $polaris->graph();
        $events->listen(...$polaris->listeners());
        $organizationId = self::organization($polaris, 'ada@example.com');
        $providers = $graph->get(Providers::class);
        $provider = $providers->create($organizationId, Provider::OIDC, 'Okta', 'https://acme.okta.com', ['client_id' => 'c1'], [], ['enabled' => true, 'roles' => ['member']], ['https://app.example/done', 'https://app.example/other'], true, null);
        $domain = $graph->get(Domains::class)->add($organizationId, $provider->id, 'ACME.example');
        $sso = $graph->get(SsoService::class);
        $client = new ClientContext('203.0.113.7', 'ua/1');

        $this->refused(fn() => $sso->start('carol@acme.example', null, null), SsoException::PROVIDER_NOT_FOUND, 'the domain is not verified yet');
        $graph->get(Domains::class)->markVerified($domain);
        $this->refused(fn() => $sso->start('carol@elsewhere.example', null, null), SsoException::PROVIDER_NOT_FOUND);
        $this->refused(fn() => $sso->start(null, null, null), SsoException::INVALID_INPUT);
        $this->refused(fn() => $sso->start('carol@acme.example', null, 'https://evil.example/'), SsoException::INVALID_INPUT, 'not one of the provider\'s redirect uris');
        $started = $sso->start('Carol@ACME.example', null, 'https://app.example/other');
        self::assertSame(['https://idp.example/authorize?client_id=c1', $provider->id, 'oidc'], [$started['url'], $started['provider_id'], $started['type']]);
        self::assertNotNull(FakeOidc::$lastState);

        $this->refused(fn() => $sso->completeOidc($provider->id, 'good', 'unknown-state', null, $client), SsoException::ASSERTION_INVALID);
        $this->refused(fn() => $sso->completeOidc($provider->id, 'bad', $this->restart($sso), null, $client), SsoException::ASSERTION_INVALID);
        $this->refused(fn() => $sso->completeOidc($provider->id, null, $this->restart($sso), 'access_denied', $client), SsoException::ASSERTION_INVALID, 'the provider refused');
        $this->refused(fn() => $sso->completeOidc('nope', 'good', $this->restart($sso), null, $client), SsoException::PROVIDER_NOT_FOUND);

        $state = $this->restart($sso, 'https://app.example/other');
        $redirect = $sso->completeOidc($provider->id, 'good', $state, null, $client);
        self::assertStringStartsWith('https://app.example/other?sso_code=', $redirect);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        $data = $sso->exchange((string) $query['sso_code']);
        self::assertSame(['Bearer', 'ada@acme.example', true], [$data['token_type'], $data['user']['email'], $data['user']['email_verified']]);
        $this->refused(fn() => $sso->exchange((string) $query['sso_code']), SsoException::CODE_INVALID, 'once');
        $this->refused(fn() => $sso->exchange('nope'), SsoException::CODE_INVALID);

        $user = $graph->users()->findOneBy(['email' => 'ada@acme.example']);
        self::assertInstanceOf(User::class, $user, 'provisioned just in time');
        self::assertSame(['Ada Lovelace', true, null], [$user->displayName, $user->emailVerifiedAt !== null, $user->passwordHash]);
        $membership = $graph->database()->findOne('auth_memberships', ['user_id' => $user->id, 'organization_id' => $organizationId]);
        self::assertSame('active', $membership['status'] ?? null);
        self::assertSame(1, $graph->database()->count('auth_membership_roles', ['membership_id' => $membership['id'] ?? '']), 'the member role');
        $claims = $graph->tokenFactory()->fromTokenString((string) $data['access_token'])->getMetadata();
        self::assertSame([$user->id, $organizationId, ['sso']], [$claims['sub'], $claims['org'], $claims['amr']]);
        self::assertContains('member', $claims['roles']);
        $loggedIn = $events->ofType(UserLoggedIn::class);
        self::assertCount(1, $loggedIn);
        self::assertSame([$user->id, ['sso'], '203.0.113.7'], [$loggedIn[0]->userId, $loggedIn[0]->amr, $loggedIn[0]->ip]);
        self::assertCount(1, $events->ofType(MemberJoined::class));
        $trail = $graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::SIGNED_IN, AuditNames::ASSERTION_REJECTED]))->events;
        self::assertSame(AuditNames::SIGNED_IN, $trail[0]->name);
        self::assertSame(['provider_id' => $provider->id, 'type' => 'oidc', 'provisioned' => true, 'joined' => true], $trail[0]->data);
        self::assertSame(['unknown or expired state', 'the code is not good', 'the provider answered access_denied'], [$trail[3]->data['reason'], $trail[2]->data['reason'], $trail[1]->data['reason']]);

        $again = $sso->completeOidc($provider->id, 'good', $this->restart($sso), null, $client);
        self::assertStringStartsWith('https://app.example/done?sso_code=', $again, 'the first redirect uri by default');
        self::assertSame(['provisioned' => false, 'joined' => false], ['provisioned' => $graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::SIGNED_IN]))->events[0]->data['provisioned'], 'joined' => $graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::SIGNED_IN]))->events[0]->data['joined']]);

        $providers->update($provider, $provider->name, $provider->issuer, ['client_id' => 'c1'], [], ['enabled' => false, 'roles' => []], $provider->redirectUris(), true);
        $user->status = User::STATUS_DISABLED;
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();
        $this->refused(fn() => $sso->completeOidc($provider->id, 'good', $this->restart($sso), null, $client), SsoException::ACCOUNT_DISABLED);
        $graph->database()->update('auth_users', ['id' => $user->id], ['email' => 'moved@acme.example']);
        $graph->identities()->clear();
        $this->refused(fn() => $sso->completeOidc($provider->id, 'good', $this->restart($sso), null, $client), SsoException::USER_UNKNOWN, 'no account and no provisioning');
        $providers->update($provider, $provider->name, $provider->issuer, ['client_id' => 'c1'], [], ['enabled' => false, 'roles' => []], $provider->redirectUris(), false);
        $this->refused(fn() => $sso->start('carol@acme.example', null, null), SsoException::PROVIDER_DISABLED);
        self::assertNotNull($sso->logout($graph->users()->find($user->id) ?? $user, $organizationId, $provider->id, null, $client));
    }

    public function testTheSamlFlowRefusesReplaysAndUnsolicitedResponsesUnlessAllowedAndLogsOutBothWays(): void
    {
        $events = new RecordingEventDispatcher();
        $polaris = self::polaris($events);
        $graph = $polaris->graph();
        $events->listen(...$polaris->listeners());
        $organizationId = self::organization($polaris, 'ada@example.com');
        $providers = $graph->get(Providers::class);
        $provider = $providers->create($organizationId, Provider::SAML, 'IdP', 'https://idp.example/metadata', ['sso_url' => 'https://idp.example/sso', 'slo_url' => 'https://idp.example/slo', 'certificate' => 'cert'], [], ['enabled' => true, 'roles' => []], ['https://app.example/done'], true, null);
        $sso = $graph->get(SsoService::class);
        $client = new ClientContext('203.0.113.7', 'ua/1');

        $started = $sso->start(null, $provider->id, null);
        self::assertSame('https://idp.example/sso?SAMLRequest=fake', $started['url']);
        $state = $this->stateOf($started);
        $this->refused(fn() => $sso->completeSaml($provider->id, 'bad', $state, $client), SsoException::ASSERTION_INVALID);
        $state = $this->stateOf($sso->start(null, $provider->id, null));
        $redirect = $sso->completeSaml($provider->id, 'good:bob@acme.example', $state, $client);
        self::assertStringStartsWith('https://app.example/done?sso_code=', $redirect);
        $bob = $graph->users()->findOneBy(['email' => 'bob@acme.example']);
        self::assertInstanceOf(User::class, $bob);
        self::assertSame(1, $graph->database()->count('auth_membership_roles', ['membership_id' => $graph->database()->findOne('auth_memberships', ['user_id' => $bob->id])['id'] ?? '']), 'the member role by default');

        $this->refused(fn() => $sso->completeSaml($provider->id, 'good:bob@acme.example', $this->stateOf($sso->start(null, $provider->id, null)), $client), SsoException::ASSERTION_INVALID, 'the assertion id was seen');
        $this->refused(fn() => $sso->completeSaml($provider->id, 'unsolicited:carol@acme.example', null, $client), SsoException::ASSERTION_INVALID, 'IdP-initiated is off');
        $this->refused(fn() => $sso->completeSaml($provider->id, null, null, $client), SsoException::ASSERTION_INVALID);
        $providers->update($provider, $provider->name, $provider->issuer, ['sso_url' => 'https://idp.example/sso', 'slo_url' => 'https://idp.example/slo', 'certificate' => 'cert', 'idp_initiated' => true], [], ['enabled' => true, 'roles' => []], ['https://app.example/done'], true);
        self::assertStringStartsWith('https://app.example/done?sso_code=', $sso->completeSaml($provider->id, 'unsolicited:carol@acme.example', null, $client), 'IdP-initiated is on');
        $reasons = [];
        foreach ($graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::ASSERTION_REJECTED]))->events as $event) {
            $reasons[] = $event->data['reason'];
        }
        self::assertSame(['no SAMLResponse in the callback', 'unsolicited response and the provider does not allow IdP-initiated sign-in', 'assertion assertion-bob@acme.example replayed', 'the response is not good'], $reasons);

        self::assertSame('https://idp.example/slo?SAMLResponse=fake-response&InResponseTo=logout-request-1', $sso->idpLogout($provider->id, ['SAMLRequest' => 'logout:bob@acme.example'], true, $client));
        $slo = $graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::SLO_COMPLETED]))->events[0];
        self::assertSame(['idp', 1, $bob->id], [$slo->data['direction'], $slo->data['sessions_revoked'], $slo->subjectId]);
        $this->refused(fn() => $sso->idpLogout($provider->id, ['SAMLRequest' => 'bogus'], true, $client), SsoException::ASSERTION_INVALID);
        self::assertSame('https://idp.example/slo?SAMLRequest=fake-logout', $sso->logout($bob, $organizationId, null, null, $client));
        $this->refused(fn() => $sso->logout($bob, 'other-org', null, null, $client), SsoException::PROVIDER_NOT_FOUND);
    }

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, string $reason, string $message = ''): void
    {
        try {
            $call();
            self::fail($message === '' ? 'expected ' . $reason : $message);
        } catch (SsoException $exception) {
            self::assertSame($reason, $exception->reason, $message);
        }
    }

    private function restart(SsoService $sso, ?string $redirectUri = null): string
    {
        return $this->stateOf($sso->start('ada@acme.example', null, $redirectUri));
    }

    /**
     * @param array{url: string, provider_id: string, type: string} $started
     */
    private function stateOf(array $started): string
    {
        $state = $started['type'] === Provider::OIDC ? FakeOidc::$lastState : FakeSaml::$lastRelayState;
        self::assertNotNull($state);

        return $state;
    }

    private static function organization(Polaris $polaris, string $ownerEmail): string
    {
        $graph = $polaris->graph();
        $owner = new User();
        $owner->id = 'u-owner';
        $owner->email = $ownerEmail;
        $owner->createdAt = $owner->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($owner);
        $graph->unitOfWork()->flush();

        return $graph->organizations()->create('Acme', null, $owner->id)->id;
    }

    private static function polaris(?RecordingEventDispatcher $events = null): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: new MutableClock(new DateTimeImmutable(self::NOW)),
            dispatcher: $events,
            plugins: [new AuditPlugin(), new AdminPlugin(), new SsoPlugin(self::BASE, oidc: new FakeOidc(), saml: new FakeSaml(), domains: new FakeVerifier())],
        ));
    }
}

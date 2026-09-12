<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Functional;

use Override;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Keys;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Audit\AuditPlugin;
use Polaris\Event\UserRegistered;
use Polaris\Sso\SsoPlugin;
use Polaris\Sso\Tests\Support\FakeOidc;
use Polaris\Sso\Tests\Support\FakeSaml;
use Polaris\Sso\Tests\Support\FakeVerifier;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_key_last;
use function dirname;
use function preg_replace;

/**
 * The sso routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with the audit
 * and admin plugins under them and the fake protocols, so every step is deterministic; the recorded
 * steps in tests/Contract/fixtures replay identically.
 */
abstract class SsoTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';
    protected const string BASE = 'https://app.example/auth';
    protected const string DONE = 'https://app.example/done';

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new AdminPlugin(), new SsoPlugin(self::BASE, oidc: new FakeOidc('ada@acme.example'), saml: new FakeSaml(), domains: new FakeVerifier())];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    protected function setUp(): void
    {
        parent::setUp();
        FakeVerifier::$verifiable = [];
        FakeOidc::$problems = [];
    }

    /**
     * Registers (once), verifies and logs the user in; their access token.
     */
    protected function login(string $email): string
    {
        $register = $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        if ($register->getStatusCode() < 300) {
            $registered = $this->events->ofType(UserRegistered::class);
            $this->postJson('/auth/email/verify', ['token' => $registered[array_key_last($registered)]->verificationToken]);
            $this->unitOfWork->clear();
        }

        return (string) ($this->json($this->postJson('/auth/login', ['email' => $email, 'password' => self::PASSWORD]))['data']['access_token'] ?? '');
    }

    /**
     * An organization the user owns; their access token switched to it.
     *
     * @return array{string, string} organization id, access token
     */
    protected function organization(string $name, string $access): array
    {
        $id = (string) ($this->json($this->authedPostJson('/orgs', ['name' => $name], $access))['data']['id'] ?? '');
        $switched = (string) ($this->json($this->authedPostJson('/auth/switch-org', ['organization_id' => $id], $access))['data']['access_token'] ?? '');

        return [$id, $switched];
    }

    /**
     * @return array<string, mixed>
     */
    protected function oidcProvider(): array
    {
        return ['type' => 'oidc', 'name' => 'Okta', 'issuer' => 'https://acme.okta.example', 'config' => ['client_id' => 'client-1', 'client_secret' => 'shh'], 'jit' => ['enabled' => true, 'roles' => ['member']], 'redirect_uris' => [self::DONE]];
    }

    /**
     * @return array<string, mixed>
     */
    protected function samlProvider(): array
    {
        return ['type' => 'saml', 'name' => 'Acme IdP', 'issuer' => 'https://idp.example/metadata', 'config' => ['sso_url' => 'https://idp.example/sso', 'slo_url' => 'https://idp.example/slo', 'certificate' => 'MIIC...'], 'attributes' => ['email' => 'mail'], 'jit' => ['enabled' => true, 'roles' => ['member']], 'redirect_uris' => [self::DONE]];
    }

    protected function key(Role $role, string $scope = Principal::SCOPE_INSTANCE): string
    {
        return $this->graph->get(Keys::class)->create('test', $role, $scope, [], null, 'test')->plaintext;
    }

    /**
     * @return array<string, mixed>
     */
    protected function problem(ResponseInterface $response, int $status, string $error, string $message = ''): array
    {
        self::assertSame($status, $response->getStatusCode(), $message);
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        $body = $this->json($response);
        self::assertSame($error, $body['error']);
        self::assertSame('https://polaris.univeros.io/problems/' . preg_replace('/_/', '/', $error, 1), $body['type'], 'the type URL matches the error code');

        return $body;
    }
}

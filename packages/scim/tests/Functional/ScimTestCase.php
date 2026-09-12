<?php

declare(strict_types=1);

namespace Polaris\Scim\Tests\Functional;

use Laminas\Diactoros\ServerRequestFactory;
use Override;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Keys;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Audit\AuditPlugin;
use Polaris\Event\UserRegistered;
use Polaris\Scim\ScimPlugin;
use Polaris\Sso\SsoPlugin;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_key_last;
use function dirname;
use function is_string;
use function parse_str;
use function parse_url;
use function preg_replace;

use const PHP_URL_QUERY;

/**
 * The scim routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with the
 * audit, admin and sso plugins under them; the recorded steps in tests/Contract/fixtures replay identically.
 */
abstract class ScimTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';
    protected const string BASE = 'https://app.example/auth';

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new AdminPlugin(), new SsoPlugin(self::BASE), new ScimPlugin(self::BASE)];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
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
     * @return array{string, string} organization id, access token switched to it
     */
    protected function organization(string $name, string $access): array
    {
        $id = (string) ($this->json($this->authedPostJson('/orgs', ['name' => $name], $access))['data']['id'] ?? '');
        $switched = (string) ($this->json($this->authedPostJson('/auth/switch-org', ['organization_id' => $id], $access))['data']['access_token'] ?? '');

        return [$id, $switched];
    }

    /**
     * @return array{string, string} connection id, its token
     */
    protected function connection(string $organizationId, string $access, string $name = 'Okta', string $deprovision = 'deactivate'): array
    {
        $data = $this->json($this->authedPostJson('/orgs/' . $organizationId . '/scim/connections', ['name' => $name, 'deprovision' => $deprovision], $access))['data'];

        return [(string) $data['id'], (string) $data['token']];
    }

    /**
     * A request as a directory sends it: any method, a JSON body, the connection token as bearer.
     *
     * @param array<string, mixed> $body
     */
    protected function scim(string $method, string $path, array $body = [], ?string $token = null): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, $path);
        $query = parse_url($path, PHP_URL_QUERY);
        if (is_string($query) && $query !== '') {
            parse_str($query, $params);
            $request = $request->withQueryParams($params);
        }
        if ($body !== []) {
            $request = $request->withHeader('Content-Type', 'application/scim+json')->withParsedBody($body);
        }

        return $this->handle($token === null ? $request : $this->withToken($request, $token));
    }

    protected function key(Role $role, string $scope = Principal::SCOPE_INSTANCE): string
    {
        return $this->graph->get(Keys::class)->create('test', $role, $scope, [], null, 'test')->plaintext;
    }

    /**
     * @return array<string, mixed>
     */
    protected function scimError(ResponseInterface $response, int $status, ?string $scimType = null): array
    {
        self::assertSame($status, $response->getStatusCode());
        self::assertSame('application/scim+json', $response->getHeaderLine('Content-Type'));
        $body = $this->json($response);
        self::assertSame(['urn:ietf:params:scim:api:messages:2.0:Error'], $body['schemas']);
        self::assertSame((string) $status, $body['status']);
        self::assertSame($scimType, $body['scimType'] ?? null);

        return $body;
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

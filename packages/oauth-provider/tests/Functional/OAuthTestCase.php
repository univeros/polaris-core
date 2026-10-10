<?php

declare(strict_types=1);

namespace Polaris\OAuth\Tests\Functional;

use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Override;
use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Event\UserRegistered;
use Polaris\OAuth\OAuthPlugin;
use Polaris\OAuth\Tests\Support\FakeHttp;
use Polaris\OAuth\Tests\Support\Keys;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function array_key_last;
use function base64_decode;
use function base64_encode;
use function dirname;
use function explode;
use function http_build_query;
use function json_decode;
use function strtr;

/**
 * The OAuth routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with the
 * audit and admin plugins under them and a fake HTTP client answering the client ID metadata documents;
 * the recorded steps in tests/Contract/fixtures replay identically.
 */
abstract class OAuthTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';
    protected const string BASE = 'https://auth.polaris.test';
    protected const string CONSENT = 'https://app.polaris.test/consent';
    protected const string DEVICE = 'https://app.polaris.test/device';
    protected const string REDIRECT = 'https://cli.polaris.test/callback';

    protected static FakeHttp $http;
    protected Keys $keys;

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new AdminPlugin(), new OAuthPlugin(
            baseUrl: self::BASE,
            consentUrl: self::CONSENT,
            deviceUrl: self::DEVICE,
            httpClient: self::$http,
            requestFactory: new RequestFactory(),
            dynamicRegistration: static::dynamicRegistration(),
            pollInterval: 0,
            scopes: ['deploy' => 'Deploy the application'],
        )];
    }

    protected static function dynamicRegistration(): bool
    {
        return false;
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    protected function setUp(): void
    {
        self::$http = new FakeHttp();
        $this->keys = new Keys();
        parent::setUp();
    }

    /**
     * Registers, verifies and logs the user in; their id and access token.
     *
     * @return array{string, string}
     */
    protected function login(string $email): array
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        $registered = $this->events->ofType(UserRegistered::class);
        $user = $registered[array_key_last($registered)];
        $this->postJson('/auth/email/verify', ['token' => $user->verificationToken]);
        $this->unitOfWork->clear();

        return [$user->userId, (string) ($this->json($this->postJson('/auth/login', ['email' => $email, 'password' => self::PASSWORD]))['data']['access_token'] ?? '')];
    }

    /**
     * Creates an organization for the session and switches to it; the organization id and the switched
     * access token.
     *
     * @return array{string, string}
     */
    protected function organization(string $access, string $name): array
    {
        $orgId = (string) $this->json($this->authedPostJson('/orgs', ['name' => $name], $access))['data']['id'];
        $switched = $this->authedPostJson('/auth/switch-org', ['organization_id' => $orgId], $access);
        self::assertSame(200, $switched->getStatusCode(), (string) $switched->getBody());

        return [$orgId, (string) $this->json($switched)['data']['access_token']];
    }

    /**
     * Registers a client for the organization; its record (with `client_secret` when it has one).
     *
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    protected function client(string $access, string $orgId, array $fields): array
    {
        $created = $this->authedPostJson('/orgs/' . $orgId . '/oauth/clients', ['name' => 'Acme CLI', 'redirect_uris' => [self::REDIRECT], ...$fields], $access);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());

        return $this->json($created)['data'];
    }

    /**
     * A form-encoded POST, as RFC 6749 clients send.
     *
     * @param array<string, mixed> $fields
     * @param array<string, string> $headers
     */
    protected function form(string $path, array $fields, array $headers = []): ResponseInterface
    {
        $request = $this->request('POST', $path)->withHeader('Content-Type', 'application/x-www-form-urlencoded');
        $request->getBody()->write(http_build_query($fields));
        $request->getBody()->rewind();
        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        return $this->handle($request);
    }

    /**
     * `GET /oauth2/authorize` as an XHR client.
     *
     * @param array<string, string> $query
     */
    protected function authorize(array $query, bool $json = true): ResponseInterface
    {
        $request = $this->request('GET', '/oauth2/authorize?' . http_build_query($query))->withQueryParams($query);

        return $this->handle($json ? $request->withHeader('Accept', 'application/json') : $request);
    }

    protected function request(string $method, string $path): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest($method, self::BASE . $path);
    }

    protected static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }

    /**
     * The claims of a JWT, unverified.
     *
     * @return array<string, mixed>
     */
    protected static function claims(string $jwt): array
    {
        $parts = explode('.', $jwt);

        return (array) json_decode((string) base64_decode(strtr($parts[1] ?? '', '-_', '+/'), true), true);
    }

    /**
     * @return array<string, mixed>
     */
    protected function problem(ResponseInterface $response, int $status, string $error, string $message = ''): array
    {
        self::assertSame($status, $response->getStatusCode(), $message . ' ' . $response->getBody());
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        $body = $this->json($response);
        self::assertSame($error, $body['error'], $message);
        self::assertSame('https://polaris.univeros.io/problems/oauth/' . $error, $body['type']);

        return $body;
    }
}

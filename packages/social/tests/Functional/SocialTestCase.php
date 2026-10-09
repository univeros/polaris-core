<?php

declare(strict_types=1);

namespace Polaris\Social\Tests\Functional;

use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Event\UserRegistered;
use Polaris\Social\SocialPlugin;
use Polaris\Social\Tests\Support\RecordedProviders;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_key_last;
use function dirname;
use function parse_str;
use function parse_url;
use function preg_replace;

use const PHP_URL_QUERY;

/**
 * The social routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with the
 * audit plugin under them and the recorded providers answering, so every step is deterministic; the
 * recorded steps in tests/Contract/fixtures replay identically.
 */
abstract class SocialTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';
    protected const string BASE = 'https://auth.polaris.test';
    protected const string DONE = 'https://app.polaris.test/signed-in';

    protected static RecordedProviders $providers;

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new SocialPlugin(
            self::BASE,
            [
                'google' => ['client_id' => 'google-client', 'client_secret' => 'google-secret'],
                'github' => ['client_id' => 'github-client', 'client_secret' => 'github-secret'],
                'apple' => ['client_id' => 'com.example.app', 'team_id' => 'TEAM123', 'key_id' => 'KEY123', 'private_key' => RecordedProviders::appleClientKey()],
                'microsoft' => ['client_id' => 'ms-client', 'client_secret' => 'ms-secret', 'tenant' => 'common'],
                'acme' => ['client_id' => 'acme-client', 'client_secret' => 'acme-secret', 'definition' => RecordedProviders::acme()],
            ],
            self::$providers->http,
            new RequestFactory(),
            new StreamFactory(),
            redirectUris: [self::DONE],
            allowDifferentEmails: ['github'],
        )];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    protected function setUp(): void
    {
        self::$providers = new RecordedProviders();
        RecordedProviders::$nonce = null;
        RecordedProviders::$claims = [];
        parent::setUp();
    }

    /**
     * Registers, verifies and logs the user in; their access token.
     */
    protected function login(string $email): string
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        $registered = $this->events->ofType(UserRegistered::class);
        $this->postJson('/auth/email/verify', ['token' => $registered[array_key_last($registered)]->verificationToken]);
        $this->unitOfWork->clear();

        return (string) ($this->json($this->postJson('/auth/login', ['email' => $email, 'password' => self::PASSWORD]))['data']['access_token'] ?? '');
    }

    /**
     * Starts a flow and keeps its nonce for the minted id_token; the state.
     */
    protected function start(string $provider, ?string $access = null): string
    {
        $response = $access === null ? $this->postJson('/social/' . $provider . '/start', []) : $this->authedPostJson('/social/' . $provider . '/link', [], $access);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $started = $this->json($response)['data'];
        RecordedProviders::$nonce = RecordedProviders::param((string) $started['url'], 'nonce');

        return (string) $started['state'];
    }

    /**
     * A query parameter of a URL.
     */
    protected static function param(string $url, string $name): string
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return (string) ($query[$name] ?? '');
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

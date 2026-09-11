<?php

declare(strict_types=1);

namespace Polaris\Tests\Functional;

use Laminas\Diactoros\ServerRequestFactory;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Contract\Plugin;
use Polaris\Schema\Schema;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Polaris\Tests\Contract\Fixture;
use Polaris\Tests\Persistence\DatabaseTestCase;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\RecordingOtpMailer;
use Polaris\Tests\Support\RecordingSmsSender;
use Polaris\Tests\Support\TestKeys;

use function getenv;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function parse_url;
use function parse_str;
use function putenv;

use const PHP_URL_QUERY;

/**
 * End-to-end tests through the PSR-15 pipeline on the database the environment selects, with
 * the contract freeze: every response is compared, normalised, to what the 1.0 code answered
 * for the same test (`tests/Contract/fixtures`). `POLARIS_HARNESS` names a {@see Harness} class
 * to run the same requests through a framework's kernel instead of the bare pipeline.
 */
abstract class FunctionalTestCase extends DatabaseTestCase
{
    protected Graph $graph;
    protected Harness $harness;
    protected RecordingEventDispatcher $events;
    protected RecordingSmsSender $sms;
    protected RecordingOtpMailer $mailer;
    private ?Fixture $fixture = null;

    protected function setUp(): void
    {
        // A package's plugins declare their tables before the database base builds the schema.
        foreach (static::plugins() as $plugin) {
            Schema::register(...$plugin->schema());
        }
        parent::setUp();

        $keys = TestKeys::rsa();
        putenv('APP_KEY=app-key-for-functional-tests-0123');
        putenv('AUTH_JWT_PRIVATE_KEY=' . $keys['private']);
        putenv('AUTH_JWT_PUBLIC_KEY=' . $keys['public']);
        putenv('AUTH_ISSUER=https://auth.polaris.test');

        $this->events = new RecordingEventDispatcher();
        $this->sms = new RecordingSmsSender();
        $this->mailer = new RecordingOtpMailer();
        $this->boot();
        $this->fixture = Fixture::for(static::class . '::' . $this->name(), $this->harness::transportHeaders(), static::fixtureDirectory());
    }

    /**
     * The plugins the tests of a package run with; core's suite runs none.
     *
     * @return list<Plugin>
     */
    protected static function plugins(): array
    {
        return [];
    }

    /**
     * Where this suite's contract fixtures live; a package's functional tests point at their own.
     */
    protected static function fixtureDirectory(): string
    {
        return Fixture::directory();
    }

    /**
     * (Re)builds Polaris from the current environment; tests that change a flag call it again.
     */
    protected function boot(): void
    {
        $this->harness = self::harnessClass()::create(new Config(
            secrets: Secrets::fromEnvironment(self::environment()),
            auth: AuthConfig::fromArray(self::authConfigArray()),
            database: $this->adapter,
            mailer: $this->mailer,
            sms: $this->sms,
            dispatcher: $this->events,
            plugins: static::plugins(),
        ));
        $this->graph = $this->harness->graph();
        // A package's plugin listeners see the events the endpoints emit, as they do in a host; core's
        // own listeners stay out, as in the recorded 1.0 runs.
        $this->events->resetListeners();
        foreach ($this->graph->plugins() as $plugin) {
            $this->events->listen(...$plugin->listeners($this->graph));
        }
        // One identity map for the test and the application, as the Cycle heap was shared in 1.0.
        $this->identities = $this->graph->identities();
        $this->unitOfWork = $this->graph->unitOfWork();
    }

    protected function tearDown(): void
    {
        $this->fixture?->assertConsumed();
        foreach (['APP_KEY', 'AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY', 'AUTH_ISSUER', 'AUTH_AUDIENCE', 'AUTH_JWT_KID', 'AUTH_JWT_PREVIOUS_PUBLIC_KEY', 'AUTH_JWT_PREVIOUS_KID', 'AUTH_ACCESS_TOKEN_DENYLIST', 'AUTH_PASSWORD_BREACH_CHECK'] as $key) {
            putenv($key);
        }
        parent::tearDown();
    }

    protected function handle(ServerRequestInterface $request): ResponseInterface
    {
        $response = $this->harness->handle($request);
        $this->fixture?->compare($request, $response);

        return $response;
    }

    protected function get(string $path): ResponseInterface
    {
        return $this->handle(self::serverRequest('GET', $path));
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function postJson(string $path, array $body): ResponseInterface
    {
        $request = self::serverRequest('POST', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body);

        return $this->handle($request);
    }

    protected function authedGet(string $path, string $accessToken): ResponseInterface
    {
        return $this->handle($this->withToken(self::serverRequest('GET', $path), $accessToken));
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function authedPostJson(string $path, array $body, string $accessToken): ResponseInterface
    {
        $request = self::serverRequest('POST', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body);

        return $this->handle($this->withToken($request, $accessToken));
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function authedPatch(string $path, array $body, string $accessToken): ResponseInterface
    {
        $request = self::serverRequest('PATCH', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body);

        return $this->handle($this->withToken($request, $accessToken));
    }

    protected function authedDelete(string $path, string $accessToken): ResponseInterface
    {
        return $this->handle($this->withToken(self::serverRequest('DELETE', $path), $accessToken));
    }

    /**
     * A request as a host's PSR-7 factory builds it: the query string parsed into the query params.
     */
    private static function serverRequest(string $method, string $path): ServerRequestInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, $path);
        $query = parse_url($path, PHP_URL_QUERY);
        if (is_string($query) && $query !== '') {
            parse_str($query, $params);
            $request = $request->withQueryParams($params);
        }

        return $request;
    }

    protected function withToken(ServerRequestInterface $request, string $accessToken): ServerRequestInterface
    {
        return $request->withHeader('Authorization', 'Bearer ' . $accessToken);
    }

    /**
     * @return array<string, mixed>
     */
    protected function json(ResponseInterface $response): array
    {
        $decoded = json_decode((string) $response->getBody(), true);
        $response->getBody()->rewind();

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @return class-string<Harness>
     */
    private static function harnessClass(): string
    {
        $class = getenv('POLARIS_HARNESS');
        if (!is_string($class) || $class === '') {
            return PipelineHarness::class;
        }
        if (!is_subclass_of($class, Harness::class)) {
            throw new \RuntimeException("POLARIS_HARNESS must name a class implementing Polaris\\Tests\\Functional\\Harness, got $class");
        }

        return $class;
    }

    /**
     * @return array<string, mixed>
     */
    private static function authConfigArray(): array
    {
        $issuer = getenv('AUTH_ISSUER');
        $audience = getenv('AUTH_AUDIENCE');
        $flag = static fn(string $key): bool => in_array(getenv($key), ['1', 'true', 'on'], true);

        return [
            'issuer' => $issuer !== false && $issuer !== '' ? $issuer : 'univeros/polaris',
            'audience' => $audience !== false && $audience !== '' ? $audience : null,
            'access_token' => ['denylist' => $flag('AUTH_ACCESS_TOKEN_DENYLIST')],
            'password' => ['breach_check' => $flag('AUTH_PASSWORD_BREACH_CHECK')],
        ];
    }

    /**
     * @return array<string, string>
     */
    private static function environment(): array
    {
        $env = [];
        foreach (['APP_KEY', 'AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY', 'AUTH_JWT_KID', 'AUTH_JWT_PREVIOUS_PUBLIC_KEY', 'AUTH_JWT_PREVIOUS_KID'] as $key) {
            $value = getenv($key);
            if ($value !== false) {
                $env[$key] = $value;
            }
        }

        return $env;
    }
}

<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\Functional;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Univeros\Polaris\Tests\Contract\Fixture;
use Univeros\Polaris\Tests\Persistence\DatabaseTestCase;
use Univeros\Polaris\Tests\Support\RecordingEventDispatcher;
use Univeros\Polaris\Tests\Support\RecordingOtpMailer;
use Univeros\Polaris\Tests\Support\RecordingSmsSender;
use Univeros\Polaris\Tests\Support\TestKeys;

use function getenv;
use function in_array;
use function is_array;
use function json_decode;
use function putenv;

/**
 * End-to-end tests through the PSR-15 pipeline on the database the environment selects, with
 * the contract freeze: every response is compared, normalised, to what the 1.0 code answered
 * for the same test (`tests/Contract/fixtures`).
 */
abstract class FunctionalTestCase extends DatabaseTestCase
{
    protected Graph $graph;
    protected Pipeline $harness;
    protected RecordingEventDispatcher $events;
    protected RecordingSmsSender $sms;
    protected RecordingOtpMailer $mailer;
    private ?Fixture $fixture = null;

    protected function setUp(): void
    {
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
        $this->fixture = Fixture::for(static::class . '::' . $this->name());
    }

    /**
     * (Re)builds Polaris from the current environment; tests that change a flag call it again.
     */
    protected function boot(): void
    {
        $polaris = Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(self::environment()),
            auth: AuthConfig::fromArray(self::authConfigArray()),
            database: $this->adapter,
            mailer: $this->mailer,
            sms: $this->sms,
            dispatcher: $this->events,
        ));
        $this->graph = $polaris->graph();
        $this->harness = new Pipeline($this->graph, new ResponseFactory());
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
        return $this->handle((new ServerRequestFactory())->createServerRequest('GET', $path));
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function postJson(string $path, array $body): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body);

        return $this->handle($request);
    }

    protected function authedGet(string $path, string $accessToken): ResponseInterface
    {
        return $this->handle($this->withToken((new ServerRequestFactory())->createServerRequest('GET', $path), $accessToken));
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function authedPostJson(string $path, array $body, string $accessToken): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body);

        return $this->handle($this->withToken($request, $accessToken));
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function authedPatch(string $path, array $body, string $accessToken): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('PATCH', $path)
            ->withHeader('Content-Type', 'application/json')
            ->withParsedBody($body);

        return $this->handle($this->withToken($request, $accessToken));
    }

    protected function authedDelete(string $path, string $accessToken): ResponseInterface
    {
        return $this->handle($this->withToken((new ServerRequestFactory())->createServerRequest('DELETE', $path), $accessToken));
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

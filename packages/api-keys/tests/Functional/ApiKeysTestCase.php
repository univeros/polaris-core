<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Tests\Functional;

use Override;
use Polaris\ApiKeys\ApiKeysPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Event\UserRegistered;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_key_last;
use function dirname;
use function substr;

/**
 * The API-key routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with the
 * audit plugin under them; the recorded steps in tests/Contract/fixtures replay identically.
 */
abstract class ApiKeysTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new ApiKeysPlugin(rotationGrace: 3600)];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
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
        $created = $this->authedPostJson('/orgs', ['name' => $name], $access);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $orgId = (string) $this->json($created)['data']['id'];
        $switched = $this->authedPostJson('/auth/switch-org', ['organization_id' => $orgId], $access);
        self::assertSame(200, $switched->getStatusCode(), (string) $switched->getBody());

        return [$orgId, (string) $this->json($switched)['data']['access_token']];
    }

    /**
     * @return array<string, mixed>
     */
    protected function problem(ResponseInterface $response, int $status, string $error, string $message = ''): array
    {
        self::assertSame($status, $response->getStatusCode(), $message . ' ' . $response->getBody());
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        $body = $this->json($response);
        self::assertSame($error, $body['error']);
        self::assertSame('https://polaris.univeros.io/problems/api-keys/' . substr($error, 9), $body['type'], 'the type URL matches the error code');

        return $body;
    }
}

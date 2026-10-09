<?php

declare(strict_types=1);

namespace Polaris\Passkey\Tests\Functional;

use Override;
use Polaris\Event\UserRegistered;
use Polaris\Passkey\PasskeyPlugin;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_key_last;
use function dirname;
use function preg_replace;

/**
 * The passkey routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with a
 * software authenticator answering the ceremonies, so the recorded steps in tests/Contract/fixtures
 * carry real WebAuthn payloads and replay identically.
 */
abstract class PasskeyTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';
    protected const string ORIGIN = 'https://auth.polaris.test';

    #[Override]
    protected static function plugins(): array
    {
        return [new PasskeyPlugin([self::ORIGIN], rpName: 'Polaris tests')];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
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

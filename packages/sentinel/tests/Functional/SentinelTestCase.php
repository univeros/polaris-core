<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Tests\Functional;

use Laminas\Diactoros\ServerRequestFactory;
use Override;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Grants;
use Polaris\Admin\Keys;
use Polaris\Admin\Principal\Principal;
use Polaris\Admin\Principal\Role;
use Polaris\Audit\AuditPlugin;
use Polaris\Event\UserRegistered;
use Polaris\Sentinel\Http\SentinelMiddleware;
use Polaris\Sentinel\Provider\BotVerifier;
use Polaris\Sentinel\SentinelPlugin;
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
 * The guarded auth routes and the sentinel's admin routes through the pipeline (and, with `POLARIS_HARNESS`,
 * through every host), with the audit and admin plugins under them. Every request carries a client address
 * and the device cookie, so the signals have something to key on and no Set-Cookie lands in a fixture; the
 * recorded steps in tests/Contract/fixtures replay identically.
 */
abstract class SentinelTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';
    protected const string OPERATOR = 'operator@example.com';
    protected const string IP = '203.0.113.7';
    protected const string DEVICE = 'device-of-the-fixtures';
    abstract protected static function sentinel(): SentinelPlugin;

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new AdminPlugin(), static::sentinel()];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    /**
     * A captcha verifier that accepts the token `good`.
     */
    protected static function verifier(): BotVerifier
    {
        return new class implements BotVerifier {
            public function verify(string $token, ?string $ip): bool
            {
                return $token === 'good';
            }
        };
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function send(string $method, string $path, array $body = [], ?string $accessToken = null, string $ip = self::IP): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, $path, ['REMOTE_ADDR' => $ip])
            ->withCookieParams([SentinelMiddleware::COOKIE => self::DEVICE])
            ->withHeader('Cookie', SentinelMiddleware::COOKIE . '=' . self::DEVICE);
        $query = parse_url($path, PHP_URL_QUERY);
        if (is_string($query) && $query !== '') {
            parse_str($query, $params);
            $request = $request->withQueryParams($params);
        }
        if ($body !== []) {
            $request = $request->withHeader('Content-Type', 'application/json')->withParsedBody($body);
        }

        return $this->handle($accessToken === null ? $request : $this->withToken($request, $accessToken));
    }

    /**
     * Registers (once), verifies and logs the user in; their access token.
     */
    protected function login(string $email, ?string $captchaToken = null): string
    {
        $body = ['email' => $email, 'password' => self::PASSWORD];
        $register = $this->send('POST', '/auth/register', $captchaToken === null ? $body : [...$body, 'captcha_token' => $captchaToken]);
        if ($register->getStatusCode() < 300) {
            $registered = $this->events->ofType(UserRegistered::class);
            $this->send('POST', '/auth/email/verify', ['token' => $registered[array_key_last($registered)]->verificationToken]);
            $this->unitOfWork->clear();
        }

        return (string) ($this->json($this->send('POST', '/auth/login', $body))['data']['access_token'] ?? '');
    }

    /**
     * The operator's access token, with an instance-wide grant of `$role` (an owner by default).
     */
    protected function operator(Role $role = Role::Owner): string
    {
        $access = $this->login(self::OPERATOR);
        $row = $this->adapter->findOne('auth_users', ['email' => self::OPERATOR]);
        self::assertIsString($row['id'] ?? null);
        $this->graph->get(Grants::class)->grant($row['id'], $role, Principal::SCOPE_INSTANCE);

        return $access;
    }

    protected function key(Role $role): string
    {
        return $this->graph->get(Keys::class)->create('test', $role, Principal::SCOPE_INSTANCE, [], null, 'test')->plaintext;
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

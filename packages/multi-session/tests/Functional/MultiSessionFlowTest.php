<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Tests\Functional;

use Laminas\Diactoros\ServerRequestFactory;
use Override;
use Polaris\Event\UserRegistered;
use Polaris\MultiSession\Http\DeviceMiddleware;
use Polaris\MultiSession\MultiSessionPlugin;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_column;
use function array_key_last;
use function dirname;

/**
 * The multi-session routes through the pipeline (and, with `POLARIS_HARNESS`, through every host): two
 * accounts on one device, switching between them without signing in again, revoking one, the last
 * method. The device travels in the `X-Polaris-Device` header; the cookie is off because the hosts
 * re-serialise `Set-Cookie` (the cookie path is unit-tested). The recorded steps in
 * tests/Contract/fixtures replay identically.
 */
final class MultiSessionFlowTest extends FunctionalTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    #[Override]
    protected static function plugins(): array
    {
        return [new MultiSessionPlugin(cookie: false)];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    public function testTwoAccountsOnOneDeviceSwitchAndSignOutOneAtATime(): void
    {
        $this->register('ada@example.com');
        $this->register('grace@example.com');

        $ada = $this->send('POST', '/auth/login', ['email' => 'ada@example.com', 'password' => self::PASSWORD]);
        $device = $ada->getHeaderLine(DeviceMiddleware::HEADER);
        self::assertNotSame('', $device, 'a sign-in mints the device');
        self::assertSame(['last_method' => 'pwd'], $this->json($this->send('GET', '/multi-session/last-method', device: $device))['data']);
        $grace = $this->send('POST', '/auth/login', ['email' => 'grace@example.com', 'password' => self::PASSWORD], device: $device);
        self::assertNotSame($device, $grace->getHeaderLine(DeviceMiddleware::HEADER), 'joining the device gives it a new id');
        $device = $grace->getHeaderLine(DeviceMiddleware::HEADER);
        $ada = $this->json($ada)['data'];
        $grace = $this->json($grace)['data'];

        self::assertSame(403, $this->send('GET', '/multi-session/list', token: (string) $grace['access_token'])->getStatusCode(), 'no device');
        $list = $this->json($this->send('GET', '/multi-session/list', token: (string) $grace['access_token'], device: $device))['data'];
        self::assertSame(['grace@example.com', 'ada@example.com'], array_column(array_column($list, 'user'), 'email'));
        $adaSession = (string) $list[1]['session_id'];

        $switched = $this->json($this->send('POST', '/multi-session/switch', ['session_id' => $adaSession], (string) $grace['access_token'], $device))['data'];
        self::assertSame('ada@example.com', $switched['user']['email'], 'a fresh envelope without signing in');
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => (string) $ada['refresh_token']])->getStatusCode(), 'ada\'s old session ended');
        self::assertSame(404, $this->send('POST', '/multi-session/switch', ['session_id' => $adaSession], (string) $grace['access_token'], $device)->getStatusCode(), 'the old session is gone');

        $list = $this->json($this->send('GET', '/multi-session/list', token: (string) $switched['access_token'], device: $device))['data'];
        self::assertCount(2, $list);
        $revoked = $this->send('DELETE', '/multi-session/' . $this->graph->tokenFactory()->fromTokenString((string) $grace['access_token'])->getMetadata('sid'), token: (string) $switched['access_token'], device: $device);
        self::assertSame(['status' => 'revoked'], $this->json($revoked)['data']);
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => (string) $grace['refresh_token']])->getStatusCode(), 'grace is signed out');
        self::assertSame(['ada@example.com'], array_column(array_column($this->json($this->send('GET', '/multi-session/list', token: (string) $switched['access_token'], device: $device))['data'], 'user'), 'email'), 'ada stays');
    }

    /**
     * @param array<string, mixed>|null $body
     */
    private function send(string $method, string $path, ?array $body = null, ?string $token = null, ?string $device = null): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest($method, $path);
        if ($body !== null) {
            $request = $request->withHeader('Content-Type', 'application/json')->withParsedBody($body);
        }
        if ($token !== null) {
            $request = $this->withToken($request, $token);
        }

        return $this->handle($device === null ? $request : $request->withHeader(DeviceMiddleware::HEADER, $device));
    }

    private function register(string $email): void
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        $registered = $this->events->ofType(UserRegistered::class);
        $this->postJson('/auth/email/verify', ['token' => $registered[array_key_last($registered)]->verificationToken]);
        $this->unitOfWork->clear();
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Anonymous\Tests\Functional;

use Override;
use Polaris\Anonymous\AnonymousPlugin;
use Polaris\Event\UserRegistered;
use Polaris\Tests\Functional\FunctionalTestCase;

use function array_key_last;
use function dirname;

/**
 * The anonymous routes through the pipeline (and, with `POLARIS_HARNESS`, through every host): a guest
 * session, and its conversion into the account it signed up for, handed to the host's hook; the recorded
 * steps in tests/Contract/fixtures replay identically.
 */
final class AnonymousFlowTest extends FunctionalTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /** @var list<array{string, string}> */
    private static array $converted = [];

    #[Override]
    protected static function plugins(): array
    {
        return [new AnonymousPlugin(static function (string $guestId, string $userId): void {
            self::$converted[] = [$guestId, $userId];
        })];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    public function testAGuestSignsInAndConvertsIntoTheAccountItSignsUpFor(): void
    {
        self::$converted = [];
        $guest = $this->postJson('/anonymous/sign-in', []);
        self::assertSame(201, $guest->getStatusCode());
        $guest = $this->json($guest)['data'];
        self::assertSame([$guest['user']['id'] . '@anonymous.invalid', false], [$guest['user']['email'], $guest['user']['email_verified']]);
        self::assertSame(['anonymous'], $this->graph->tokenFactory()->fromTokenString((string) $guest['access_token'])->getMetadata('amr'));

        self::assertSame(401, $this->postJson('/anonymous/convert', ['access_token' => 'x'])->getStatusCode());
        self::assertSame('anonymous_invalid_input', $this->json($this->authedPostJson('/anonymous/convert', [], (string) $guest['access_token']))['error']);
        self::assertSame('anonymous_token_invalid', $this->json($this->authedPostJson('/anonymous/convert', ['access_token' => (string) $guest['access_token']], (string) $guest['access_token']))['error'], 'not into itself');

        $ada = $this->login('ada@example.com');
        self::assertSame('anonymous_not_a_guest', $this->json($this->authedPostJson('/anonymous/convert', ['access_token' => (string) $guest['access_token']], $ada))['error'], 'a real account is not a guest');
        $converted = $this->authedPostJson('/anonymous/convert', ['access_token' => $ada], (string) $guest['access_token']);
        self::assertSame(200, $converted->getStatusCode());
        $data = $this->json($converted)['data'];
        self::assertSame([$guest['user']['id'], 'converted'], [$data['guest_id'], $data['status']]);
        self::assertSame([[$guest['user']['id'], $data['user_id']]], self::$converted, 'the host received both ids');
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => (string) $guest['refresh_token']])->getStatusCode(), 'the guest\'s session ended');
        $again = $this->authedPostJson('/anonymous/convert', ['access_token' => $ada], (string) $guest['access_token']);
        self::assertSame([403, 'anonymous_not_a_guest'], [$again->getStatusCode(), $this->json($again)['error']], 'once');
    }

    private function login(string $email): string
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        $registered = $this->events->ofType(UserRegistered::class);
        $this->postJson('/auth/email/verify', ['token' => $registered[array_key_last($registered)]->verificationToken]);
        $this->unitOfWork->clear();

        return (string) ($this->json($this->postJson('/auth/login', ['email' => $email, 'password' => self::PASSWORD]))['data']['access_token'] ?? '');
    }
}

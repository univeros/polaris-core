<?php

declare(strict_types=1);

namespace Polaris\Username\Tests\Functional;

use Override;
use Polaris\Event\UserRegistered;
use Polaris\Tests\Functional\FunctionalTestCase;
use Polaris\Username\UsernamePlugin;

use function array_key_last;
use function dirname;

/**
 * The username routes through the pipeline (and, with `POLARIS_HARNESS`, through every host): setting a
 * username, its case-insensitive uniqueness, and signing in with it or the email through core's password
 * path; the recorded steps in tests/Contract/fixtures replay identically.
 */
final class UsernameFlowTest extends FunctionalTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    #[Override]
    protected static function plugins(): array
    {
        return [new UsernamePlugin()];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    public function testAUsernameIsUniqueWithoutRegardToCaseAndSignsInThroughThePasswordPath(): void
    {
        $ada = $this->login('ada@example.com');
        $grace = $this->login('grace@example.com');

        self::assertSame(401, $this->authedPatch('/username', ['username' => 'ada.l'], '')->getStatusCode());
        $invalid = $this->authedPatch('/username', ['username' => 'admin'], $ada);
        self::assertSame([422, 'username_invalid', ['The username is reserved.']], [$invalid->getStatusCode(), $this->json($invalid)['error'], $this->json($invalid)['errors']]);
        self::assertSame(['username' => 'ada.l', 'display_username' => 'Ada.L'], $this->json($this->authedPatch('/username', ['username' => 'Ada.L'], $ada))['data']);
        $taken = $this->authedPatch('/username', ['username' => 'ADA.l'], $grace);
        self::assertSame([409, 'username_taken'], [$taken->getStatusCode(), $this->json($taken)['error']], 'taken without regard to case');

        foreach (['ada.L', 'ADA@example.com'] as $identifier) {
            $session = $this->json($this->postJson('/username/sign-in', ['username' => $identifier, 'password' => self::PASSWORD]))['data'];
            self::assertSame('ada@example.com', $session['user']['email'], $identifier);
        }
        $unknown = $this->postJson('/username/sign-in', ['username' => 'nobody', 'password' => self::PASSWORD]);
        $wrong = $this->postJson('/username/sign-in', ['username' => 'ada.l', 'password' => 'not the password']);
        self::assertSame([401, 401], [$unknown->getStatusCode(), $wrong->getStatusCode()]);
        self::assertSame($this->json($unknown), $this->json($wrong), 'the same answer');
        self::assertSame(422, $this->postJson('/username/sign-in', ['username' => 'ada.l'])->getStatusCode());
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

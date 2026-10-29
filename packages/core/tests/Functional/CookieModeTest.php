<?php

declare(strict_types=1);

namespace Polaris\Tests\Functional;

use OTPHP\TOTP;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use Polaris\Event\UserRegistered;
use Polaris\Psr15\Middleware\RefreshCookieMiddleware;
use Psr\Http\Message\ResponseInterface;

use function time;

/**
 * Cookie token delivery on core's routes (docs/cookie-mode/spec.md §5, tests 1 to 9): the refresh
 * token moves to an `HttpOnly` cookie, every route that sets or uses it is CSRF-guarded and refused over
 * plaintext, and logout clears it. Replays through the four harnesses like the rest of the suite.
 */
final class CookieModeTest extends FunctionalTestCase
{
    use CookieRequests;

    private const string EMAIL = 'cookie@example.com';
    private const string PASSWORD = 'correct horse battery staple';
    private const string COOKIE = RefreshCookieMiddleware::COOKIE;

    #[Override]
    protected static function authConfig(): array
    {
        return ['flows' => ['token_delivery' => 'cookie']];
    }

    public function testLoginMovesTheRefreshTokenToTheCookie(): void
    {
        $this->register();

        $response = $this->login();

        self::assertSame(200, $response->getStatusCode());
        $data = $this->json($response)['data'];
        self::assertArrayNotHasKey('refresh_token', $data);
        self::assertNotSame('', $data['access_token']);
        self::assertSame('Bearer', $data['token_type']);
        self::assertArrayHasKey('expires_in', $data);
        $this->assertRefreshCookieSet($response);
        self::assertSame(200, $this->authedGet('/auth/me', (string) $data['access_token'])->getStatusCode());
    }

    public function testTheMfaTicketSetsNoCookieAndTheVerifySetsIt(): void
    {
        $access = $this->bearer($this->registerAndLogin());
        $enroll = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];
        $this->authedPostJson('/auth/mfa/totp/confirm', ['factor_id' => $enroll['factor_id'], 'code' => self::totp((string) $enroll['secret'])->now()], $access);
        $this->unitOfWork->clear();

        $ticket = $this->login();
        self::assertSame(200, $ticket->getStatusCode());
        $challenge = $this->json($ticket)['data'];
        self::assertTrue($challenge['mfa_required']);
        $this->assertNoRefreshCookie($ticket);

        $verified = $this->send(
            '/auth/mfa/verify',
            ['factor_id' => $challenge['factors'][0]['id'], 'code' => self::totp((string) $enroll['secret'])->at(time() + 30)],
            accessToken: (string) $challenge['mfa_token'],
        );
        self::assertSame(200, $verified->getStatusCode());
        $this->assertNoRefreshTokenInBody($verified);
        $this->assertRefreshCookieSet($verified);
    }

    public function testRefreshWithTheCookieRotatesIt(): void
    {
        $first = $this->assertRefreshCookieSet($this->registerAndLogin());

        $refreshed = $this->send('/auth/token/refresh', [], [self::COOKIE => $first]);

        self::assertSame(200, $refreshed->getStatusCode());
        $this->assertNoRefreshTokenInBody($refreshed);
        self::assertNotSame('', $this->json($refreshed)['data']['access_token']);
        $second = $this->assertRefreshCookieSet($refreshed);
        self::assertNotSame($first, $second);
        // The cookie's path is the refresh route, so logout and every other route never see it.
        self::assertSame(200, $this->send('/auth/token/refresh', [], [self::COOKIE => $second])->getStatusCode());
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function failingGuards(): iterable
    {
        yield 'no header' => [[]];
        yield 'a foreign Origin' => [[RefreshCookieMiddleware::CSRF_HEADER => '1', 'Origin' => 'https://evil.example']];
        yield 'Origin: null' => [[RefreshCookieMiddleware::CSRF_HEADER => '1', 'Origin' => 'null']];
        yield 'a cross-site fetch' => [[RefreshCookieMiddleware::CSRF_HEADER => '1', 'Sec-Fetch-Site' => 'cross-site']];
        yield 'the header with the wrong value' => [[RefreshCookieMiddleware::CSRF_HEADER => 'true']];
    }

    /**
     * @param array<string, string> $headers
     */
    #[DataProvider('failingGuards')]
    public function testARefreshThatFailsTheGuardIsRefusedAndConsumesNothing(array $headers): void
    {
        $cookie = $this->assertRefreshCookieSet($this->registerAndLogin());

        $refused = $this->send('/auth/token/refresh', [], [self::COOKIE => $cookie], $headers);

        self::assertSame(403, $refused->getStatusCode());
        self::assertSame(['error' => 'csrf_failed', 'message' => 'The request did not pass the CSRF check.'], $this->json($refused));
        $this->assertNoRefreshCookie($refused);
        self::assertSame(200, $this->send('/auth/token/refresh', [], [self::COOKIE => $cookie])->getStatusCode(), 'the token was not consumed');
    }

    public function testTheOwnOriginAndASameOriginFetchPassTheGuard(): void
    {
        $cookie = $this->assertRefreshCookieSet($this->registerAndLogin());

        $origin = $this->send('/auth/token/refresh', [], [self::COOKIE => $cookie], [RefreshCookieMiddleware::CSRF_HEADER => '1', 'Origin' => 'https://localhost']);
        self::assertSame(200, $origin->getStatusCode());
        $fetch = $this->send('/auth/token/refresh', [], [self::COOKIE => $this->assertRefreshCookieSet($origin)], [RefreshCookieMiddleware::CSRF_HEADER => '1', 'Sec-Fetch-Site' => 'same-origin']);
        self::assertSame(200, $fetch->getStatusCode());
    }

    public function testLoginCsrfIsRefusedBeforeASessionExists(): void
    {
        $this->register();
        $sessions = $this->adapter->count('auth_refresh_tokens', []);

        // An HTML form on another site posting the attacker's credentials (form-encoded, no header).
        $refused = $this->send('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD], [], ['Origin' => 'https://evil.example', 'Content-Type' => 'application/x-www-form-urlencoded']);

        self::assertSame(403, $refused->getStatusCode());
        self::assertSame('csrf_failed', $this->json($refused)['error']);
        $this->assertNoRefreshCookie($refused);
        self::assertSame($sessions, $this->adapter->count('auth_refresh_tokens', []), 'no session was created');
    }

    public function testARefreshTokenPlantedThroughTheBodyOrTheQueryIsRefusedWithoutTheGuard(): void
    {
        $token = $this->assertRefreshCookieSet($this->registerAndLogin());

        $form = $this->send('/auth/token/refresh', ['refresh_token' => $token], [], ['Origin' => 'https://evil.example']);
        $query = $this->send('/auth/token/refresh?refresh_token=' . $token, [], [], ['Origin' => 'https://evil.example']);

        self::assertSame(403, $form->getStatusCode());
        self::assertSame(403, $query->getStatusCode());
        self::assertSame(200, $this->send('/auth/token/refresh', [], [self::COOKIE => $token])->getStatusCode(), 'the token was not consumed');
    }

    public function testABodyTokenStillRefreshesAndItsSuccessorGoesToTheCookie(): void
    {
        $token = $this->assertRefreshCookieSet($this->registerAndLogin());

        $refreshed = $this->send('/auth/token/refresh', ['refresh_token' => $token]);

        self::assertSame(200, $refreshed->getStatusCode());
        $this->assertNoRefreshTokenInBody($refreshed);
        self::assertNotSame($token, $this->assertRefreshCookieSet($refreshed));
    }

    public function testAnInvalidBodyTokenLeavesAValidCookieAlone(): void
    {
        $cookie = $this->assertRefreshCookieSet($this->registerAndLogin());

        $failed = $this->send('/auth/token/refresh', ['refresh_token' => 'not-a-token'], [self::COOKIE => $cookie]);

        self::assertSame(401, $failed->getStatusCode());
        $this->assertNoRefreshCookie($failed);
        self::assertSame(200, $this->send('/auth/token/refresh', [], [self::COOKIE => $cookie])->getStatusCode());
    }

    public function testReplayingARotatedCookieRevokesTheFamilyAndClearsIt(): void
    {
        $first = $this->assertRefreshCookieSet($this->registerAndLogin());
        $second = $this->assertRefreshCookieSet($this->send('/auth/token/refresh', [], [self::COOKIE => $first]));

        $replay = $this->send('/auth/token/refresh', [], [self::COOKIE => $first]);

        self::assertSame(401, $replay->getStatusCode());
        $this->assertRefreshCookieCleared($replay);
        self::assertSame(401, $this->send('/auth/token/refresh', [], [self::COOKIE => $second])->getStatusCode(), 'the family is revoked');
    }

    public function testLogoutAndLogoutAllClearTheCookie(): void
    {
        $access = $this->bearer($this->registerAndLogin());
        $logout = $this->send('/auth/logout', accessToken: $access);
        self::assertSame(200, $logout->getStatusCode());
        $this->assertRefreshCookieCleared($logout);

        $all = $this->send('/auth/logout-all', accessToken: $this->bearer($this->login()));
        self::assertSame(200, $all->getStatusCode());
        $this->assertRefreshCookieCleared($all);
    }

    public function testAFailedLogoutLeavesTheCookie(): void
    {
        $refused = $this->send('/auth/logout', accessToken: 'not-a-jwt');

        self::assertSame(401, $refused->getStatusCode());
        $this->assertNoRefreshCookie($refused);
    }

    /**
     * @return iterable<string, array{string, array<string, string>}>
     */
    public static function plaintextRoutes(): iterable
    {
        yield 'login' => ['/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]];
        yield 'refresh' => ['/auth/token/refresh', ['refresh_token' => 'x']];
    }

    /**
     * @param array<string, string> $body
     */
    #[DataProvider('plaintextRoutes')]
    public function testPlaintextIsRefusedBeforeTheHandler(string $path, array $body): void
    {
        $this->register();
        $sessions = $this->adapter->count('auth_refresh_tokens', []);

        $refused = $this->send($path, $body, scheme: 'http');

        self::assertSame(403, $refused->getStatusCode());
        self::assertSame(['error' => 'insecure_transport', 'message' => 'Sessions are only issued over HTTPS.'], $this->json($refused));
        $this->assertNoRefreshCookie($refused);
        self::assertSame($sessions, $this->adapter->count('auth_refresh_tokens', []));
    }

    public function testRoutesWithoutTheSessionKeyAreUntouched(): void
    {
        // Registration is not a session route: no guard, no scheme check, no cookie.
        $response = $this->postJson('/auth/register', ['email' => 'plain@example.com', 'password' => self::PASSWORD]);

        self::assertSame(202, $response->getStatusCode());
        $this->assertNoRefreshCookie($response);
    }

    private function register(): void
    {
        $this->postJson('/auth/register', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $token = $this->events->ofType(UserRegistered::class)[0]->verificationToken;
        $this->postJson('/auth/email/verify', ['token' => $token]);
        $this->unitOfWork->clear();
    }

    private function registerAndLogin(): ResponseInterface
    {
        $this->register();

        return $this->login();
    }

    private function login(): ResponseInterface
    {
        return $this->send('/auth/login', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
    }

    private function bearer(ResponseInterface $response): string
    {
        return (string) ($this->json($response)['data']['access_token'] ?? '');
    }

    private static function totp(string $secret): TOTP
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setPeriod(30);
        $totp->setDigits(6);
        $totp->setDigest('sha1');

        return $totp;
    }
}

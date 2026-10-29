<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Tests\Functional;

use Override;
use Polaris\Event\UserRegistered;
use Polaris\MultiSession\Http\DeviceMiddleware;
use Polaris\MultiSession\MultiSessionPlugin;
use Polaris\Tests\Functional\CookieRequests;
use Polaris\Tests\Functional\FunctionalTestCase;

use function array_column;
use function array_key_last;

/**
 * Cookie token delivery with `polaris/multi-session` (docs/cookie-mode/spec.md §5, tests 8 and 12): the
 * device middleware still recognises a new session (it runs inside the cookie middleware and sees the
 * body-mode response), its own cookie survives next to the refresh cookie, and the switch, an `issue`
 * route, hands the other account's refresh token to the cookie.
 */
final class CookieModeTest extends FunctionalTestCase
{
    use CookieRequests;

    private const string PASSWORD = 'correct horse battery staple';

    #[Override]
    protected static function plugins(): array
    {
        return [new MultiSessionPlugin()];
    }

    #[Override]
    protected static function authConfig(): array
    {
        return ['flows' => ['token_delivery' => 'cookie']];
    }

    public function testSignInsAreRecordedAgainstTheDeviceAndTheSwitchSetsTheCookie(): void
    {
        $this->register('ada@example.com');
        $this->register('grace@example.com');

        $ada = $this->send('/auth/login', ['email' => 'ada@example.com', 'password' => self::PASSWORD]);
        self::assertSame(200, $ada->getStatusCode());
        $this->assertNoRefreshTokenInBody($ada);
        $this->assertRefreshCookieSet($ada);
        $device = self::cookies($ada)[DeviceMiddleware::COOKIE]['value'] ?? '';
        self::assertNotSame('', $device, 'the device cookie is set beside the refresh cookie');

        $grace = $this->send('/auth/login', ['email' => 'grace@example.com', 'password' => self::PASSWORD], [DeviceMiddleware::COOKIE => $device]);
        self::assertSame(200, $grace->getStatusCode());
        $this->assertRefreshCookieSet($grace);
        $device = self::cookies($grace)[DeviceMiddleware::COOKIE]['value'] ?? '';
        $graceAccess = (string) $this->json($grace)['data']['access_token'];

        $list = $this->json($this->send('/multi-session/list', cookies: [DeviceMiddleware::COOKIE => $device], accessToken: $graceAccess, method: 'GET'))['data'];
        self::assertSame(['grace@example.com', 'ada@example.com'], array_column(array_column($list, 'user'), 'email'), 'both cookie-mode sign-ins are on the device');

        $switched = $this->send('/multi-session/switch', ['session_id' => (string) $list[1]['session_id']], [DeviceMiddleware::COOKIE => $device], accessToken: $graceAccess);
        self::assertSame(200, $switched->getStatusCode());
        self::assertSame('ada@example.com', $this->json($switched)['data']['user']['email']);
        $this->assertNoRefreshTokenInBody($switched);
        $this->assertRefreshCookieSet($switched);
    }

    private function register(string $email): void
    {
        $this->postJson('/auth/register', ['email' => $email, 'password' => self::PASSWORD]);
        $registered = $this->events->ofType(UserRegistered::class);
        $this->postJson('/auth/email/verify', ['token' => $registered[array_key_last($registered)]->verificationToken]);
        $this->unitOfWork->clear();
    }
}

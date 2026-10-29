<?php

declare(strict_types=1);

namespace Polaris\Tests\Http\Manifest;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\Loader;

use function array_filter;
use function array_keys;
use function array_values;
use function dirname;
use function file_put_contents;
use function glob;
use function in_array;
use function is_array;
use function mkdir;
use function sort;
use function sys_get_temp_dir;
use function uniqid;

/**
 * Cookie token delivery moves the refresh token of every route marked `session: issue | refresh`
 * (docs/cookie-mode/spec.md §2.2). A route that answers a refresh token without the mark would hand it
 * over in the body in cookie mode, silently: this walks core's manifest and every plugin's and fails on one.
 */
#[CoversClass(Loader::class)]
#[CoversClass(EndpointSpec::class)]
final class SessionCoverageTest extends TestCase
{
    /** Routes whose refresh token is not the caller's session: the OAuth provider's belongs to an OAuth client (RFC 6749). */
    private const array EXCEPTIONS = ['POST /oauth2/token'];

    public function testEveryRouteThatAnswersARefreshTokenIsMarked(): void
    {
        $unmarked = [];
        $exceptions = [];
        foreach ($this->manifest() as $spec) {
            if (!self::answersRefreshToken($spec)) {
                continue;
            }
            if (in_array($spec->route(), self::EXCEPTIONS, true)) {
                $exceptions[] = $spec->route();
                self::assertNull($spec->session, $spec->route() . ' is an exception and must stay unmarked');
                continue;
            }
            if (!in_array($spec->session, ['issue', 'refresh'], true)) {
                $unmarked[] = $spec->route();
            }
        }

        self::assertSame([], $unmarked, 'answer data.refresh_token without session: issue | refresh');
        self::assertSame(self::EXCEPTIONS, $exceptions, 'every exception still exists');
    }

    public function testTheMarkedRoutesAreTheOnesTheSpecNames(): void
    {
        $marked = [];
        foreach ($this->manifest() as $spec) {
            if ($spec->session !== null) {
                $marked[$spec->session][] = $spec->route();
            }
        }
        foreach (array_keys($marked) as $session) {
            sort($marked[$session]);
        }

        self::assertSame([
            'issue' => [
                'POST /anonymous/sign-in',
                'POST /auth/login',
                'POST /auth/mfa/verify',
                'POST /email-otp/verify',
                'POST /magic-link/exchange',
                'POST /multi-session/switch',
                'POST /one-time-token/verify',
                'POST /passkey/authenticate/verify',
                'POST /phone/verify',
                'POST /social/exchange',
                'POST /social/google/one-tap',
                'POST /sso/exchange',
                'POST /username/sign-in',
            ],
            'refresh' => ['POST /auth/token/refresh'],
            'end' => ['POST /auth/logout', 'POST /auth/logout-all', 'POST /sso/logout'],
        ], ['issue' => $marked['issue'] ?? [], 'refresh' => $marked['refresh'] ?? [], 'end' => $marked['end'] ?? []]);
    }

    public function testAnUnknownSessionValueIsRejected(): void
    {
        $directory = sys_get_temp_dir() . '/polaris-session-' . uniqid();
        mkdir($directory);
        file_put_contents($directory . '/x.yaml', "endpoint: { method: POST, path: /x, auth: public, effect: write, session: open }\ndomain: { class: " . self::class . " }\n");

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('x.yaml: unknown session "open".');
        (new Loader($directory))->load();
    }

    /**
     * @return list<EndpointSpec>
     */
    private function manifest(): array
    {
        $packages = dirname(__DIR__, 4);
        $plugins = glob($packages . '/*/api') ?: [];
        $plugins = array_values(array_filter($plugins, static fn(string $dir): bool => $dir !== $packages . '/core/api'));

        return (new Loader(Loader::defaultDirectory(), ...$plugins))->load()->endpoints();
    }

    private static function answersRefreshToken(EndpointSpec $spec): bool
    {
        foreach ($spec->outputExamples as $example) {
            $data = $example['data'] ?? null;
            if ((is_array($data) && isset($data['refresh_token'])) || isset($example['refresh_token'])) {
                return true;
            }
        }

        return false;
    }
}

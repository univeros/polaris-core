<?php

declare(strict_types=1);

namespace Polaris\Mcp\Tests\Functional;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Override;
use Polaris\Event\UserRegistered;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Mcp\Principal;
use Polaris\Mcp\Server\Dispatcher;
use Polaris\Tests\Functional\FunctionalTestCase;

/**
 * A tool call has no cookie jar, so `polaris/mcp`'s dispatcher runs its pipeline in body mode whatever
 * the host's token delivery (docs/cookie-mode/spec.md §2.11, §5 test 13): the login tool answers the
 * refresh token in its body, even over http and without the CSRF header the HTTP route would demand.
 */
final class CookieModeTest extends FunctionalTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    #[Override]
    protected static function authConfig(): array
    {
        return ['flows' => ['token_delivery' => 'cookie']];
    }

    public function testTheLoginToolAnswersTheRefreshTokenInItsBody(): void
    {
        $this->postJson('/auth/register', ['email' => 'tool@example.com', 'password' => self::PASSWORD]);
        $this->postJson('/auth/email/verify', ['token' => $this->events->ofType(UserRegistered::class)[0]->verificationToken]);
        $this->unitOfWork->clear();
        $login = $this->spec('POST /auth/login');
        self::assertSame('issue', $login->session);

        $dispatcher = new Dispatcher($this->graph, new ServerRequestFactory(), new ResponseFactory(), new StreamFactory(), 'http://localhost');
        $result = $dispatcher->call($login, ['email' => 'tool@example.com', 'password' => self::PASSWORD], Principal::anonymous());

        self::assertSame(200, $result['status']);
        self::assertIsArray($result['body']);
        self::assertNotSame('', $result['body']['data']['refresh_token'] ?? '');
    }

    private function spec(string $route): EndpointSpec
    {
        foreach ($this->graph->manifest()->endpoints() as $spec) {
            if ($spec->route() === $route) {
                return $spec;
            }
        }
        self::fail($route . ' is not in the manifest');
    }
}

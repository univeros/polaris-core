<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Tests\Functional;

use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Event\UserRegistered;
use Polaris\Messaging\Channel\ArrayChannel;
use Polaris\Messaging\Message;
use Polaris\Messaging\MessagingPlugin;
use Polaris\Passwordless\PasswordlessPlugin;
use Polaris\Tests\Functional\FunctionalTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_key_last;
use function dirname;
use function parse_str;
use function parse_url;
use function preg_replace;

use const PHP_URL_QUERY;

/**
 * The passwordless routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with
 * messaging sending into array channels the tests read the links and codes from; the recorded steps in
 * tests/Contract/fixtures replay identically.
 */
abstract class PasswordlessTestCase extends FunctionalTestCase
{
    protected const string PASSWORD = 'correct horse battery staple';
    protected const string BASE = 'https://app.example/auth';
    protected const string DONE = 'https://app.example/signed-in';

    protected static ArrayChannel $mail;
    protected static ArrayChannel $phone;

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new MessagingPlugin(channels: [self::$mail, self::$phone], caps: ['*' => [100, 600]]), new PasswordlessPlugin(self::BASE, [self::DONE])];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    protected function setUp(): void
    {
        self::$mail = new ArrayChannel('mail', [Message::EMAIL]);
        self::$phone = new ArrayChannel('sms', [Message::SMS]);
        parent::setUp();
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
     * The last code sent through the channel.
     */
    protected static function code(ArrayChannel $channel): string
    {
        return (string) $channel->messages[array_key_last($channel->messages)]->vars['code'];
    }

    /**
     * A query parameter of a URL.
     */
    protected static function param(string $url, string $name): string
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return (string) ($query[$name] ?? '');
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

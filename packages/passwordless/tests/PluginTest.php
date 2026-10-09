<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Tests;

use DateTimeImmutable;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Anonymous\AnonymousPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\PasswordChanged;
use Polaris\Event\UserEmailVerified;
use Polaris\Event\UserLoggedIn;
use Polaris\Event\UserRegistered;
use Polaris\Messaging\Channel\ArrayChannel;
use Polaris\Messaging\Message;
use Polaris\Messaging\MessagingPlugin;
use Polaris\Model\User;
use Polaris\Passwordless\EmailOtp;
use Polaris\Passwordless\MagicLinks;
use Polaris\Passwordless\OneTimeTokens;
use Polaris\Passwordless\PasswordlessException;
use Polaris\Passwordless\PasswordlessPlugin;
use Polaris\Passwordless\Phones;
use Polaris\Passwordless\PhoneSignIn;
use Polaris\Passwordless\Schema;
use Polaris\Passwordless\SecretStore;
use Polaris\Passwordless\Sessions;
use Polaris\Passwordless\Settings;
use Polaris\Polaris;
use Polaris\Psr15\Pipeline;
use Polaris\Sentinel\Http\SentinelMiddleware;
use Polaris\Sentinel\Model\IpRule;
use Polaris\Sentinel\IpRules;
use Polaris\Sentinel\SentinelPlugin;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Username\UsernamePlugin;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function array_key_last;
use function count;
use function in_array;
use function json_decode;
use function parse_str;
use function parse_url;
use function str_repeat;

use const PHP_URL_QUERY;

/**
 * The plugin wired through `Polaris::create()` and the four methods through their services: the
 * envelope and `amr` each ends in, single use, expiry, attempts, anonymous sends, sign-up, core's MFA
 * gate, and sentinel guarding the new routes. Separate processes: the schema registry is static.
 */
#[CoversClass(PasswordlessPlugin::class)]
#[CoversClass(Settings::class)]
#[CoversClass(SecretStore::class)]
#[CoversClass(Sessions::class)]
#[CoversClass(MagicLinks::class)]
#[CoversClass(EmailOtp::class)]
#[CoversClass(PhoneSignIn::class)]
#[CoversClass(Phones::class)]
#[CoversClass(OneTimeTokens::class)]
#[CoversClass(PasswordlessException::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-09T10:00:00+00:00';
    private const string BASE = 'https://app.example/auth';
    private const string DONE = 'https://app.example/signed-in';
    private const string OTHER = 'https://app.example/other?tab=1';
    private const string PASSWORD = 'correct horse battery staple';

    private ArrayChannel $mail;
    private ArrayChannel $sms;
    private MutableClock $clock;
    private RecordingEventDispatcher $events;
    private ClientContext $client;

    protected function setUp(): void
    {
        $this->mail = new ArrayChannel('mail', [Message::EMAIL]);
        $this->sms = new ArrayChannel('sms', [Message::SMS]);
        $this->clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $this->events = new RecordingEventDispatcher();
        $this->client = new ClientContext('203.0.113.7', 'ua/1');
    }

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();

        self::assertArrayHasKey(Schema::SECRETS, self::tables($polaris));
        self::assertArrayHasKey(Schema::PHONES, self::tables($polaris));
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (in_array('passwordless', $spec->tags, true)) {
                $graph->endpoint($spec->class);
                $routes[] = $spec->method . ' ' . $spec->path;
            }
        }
        self::assertCount(13, $routes);
        foreach (['POST /magic-link/send', 'GET /magic-link/verify', 'POST /magic-link/exchange', 'POST /email-otp/send', 'POST /email-otp/verify', 'POST /email-otp/verify-email', 'POST /email-otp/reset-password', 'POST /phone/send', 'POST /phone/verify', 'POST /phone/add', 'POST /phone/confirm', 'POST /one-time-token/generate', 'POST /one-time-token/verify'] as $route) {
            self::assertContains($route, $routes);
        }
        foreach (PasswordlessPlugin::SENTINEL_ROUTES as $path => $kind) {
            self::assertContains('POST ' . $path, $routes, 'sentinel guards a route the plugin has');
        }
        self::assertSame(PasswordlessPlugin::ID, PasswordlessPlugin::of($graph)->id());
        self::assertSame(self::BASE, PasswordlessPlugin::of($graph)->settings()->baseUrl);

        foreach ([static fn() => new Settings('/auth'), static fn() => new Settings(self::BASE, otpLength: 4)] as $invalid) {
            try {
                $invalid();
                self::fail('the settings are validated');
            } catch (LogicException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testAMagicLinkSignsUpOnceAndRedirectsWithAOneUseCode(): void
    {
        $graph = $this->polaris()->graph();
        $links = $graph->get(MagicLinks::class);
        $sessions = $graph->get(Sessions::class);

        $links->send('Ada@Example.com', null);
        $token = $this->linkToken();
        self::assertSame('ada@example.com', $this->mail->messages[0]->to);
        $redirect = $links->verify($token, $this->client);
        self::assertStringStartsWith(self::DONE . '?code=', $redirect);
        $data = $sessions->exchange(self::query($redirect)['code']);
        self::assertSame(['Bearer', 'ada@example.com', true], [$data['token_type'], $data['user']['email'], $data['user']['email_verified']]);
        self::assertSame([MagicLinks::AMR], $this->claims($graph, $data)['amr']);
        $user = $graph->users()->findOneBy(['email' => 'ada@example.com']);
        self::assertInstanceOf(User::class, $user, 'signed up');
        self::assertNull($user->passwordHash);
        self::assertSame([], $this->events->ofType(UserRegistered::class), 'no verification mail for a proven mailbox');
        self::assertSame([MagicLinks::AMR], $this->events->ofType(UserLoggedIn::class)[0]->amr);

        $this->refused(fn() => $links->verify($token, $this->client), PasswordlessException::TOKEN_INVALID, 'a link works once');
        $this->refused(fn() => $sessions->exchange(self::query($redirect)['code']), PasswordlessException::TOKEN_INVALID, 'a code works once');
        $this->refused(fn() => $links->send('ada@example.com', 'https://evil.example/'), PasswordlessException::REDIRECT_NOT_ALLOWED);

        $links->send('ada@example.com', self::OTHER);
        self::assertStringStartsWith(self::OTHER . '&code=', $links->verify($this->linkToken(), $this->client), 'the allowed redirect, its query kept');
        $links->send('ada@example.com', null);
        $this->clock->advance('+16 minutes');
        $this->refused(fn() => $links->verify($this->linkToken(), $this->client), PasswordlessException::TOKEN_INVALID, 'a link lives 15 minutes');

        $user->status = User::STATUS_DISABLED;
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();
        $sent = count($this->mail->messages);
        $links->send('ada@example.com', null);
        self::assertCount($sent, $this->mail->messages, 'a disabled account gets nothing, and the caller answers the same');
    }

    public function testWithoutSignUpAnUnknownAddressGetsNothingAndTheSameRefusal(): void
    {
        $graph = $this->polaris(new PasswordlessPlugin(self::BASE, [self::DONE], signUp: false))->graph();

        $graph->get(MagicLinks::class)->send('nobody@example.com', null);
        $graph->get(EmailOtp::class)->send('nobody@example.com', EmailOtp::SIGN_IN);
        self::assertSame([], $this->mail->messages);
        $this->refused(fn() => $graph->get(EmailOtp::class)->signIn('nobody@example.com', '123456', $this->client), PasswordlessException::CODE_INVALID);
        $this->refused(fn() => $graph->get(Sessions::class)->forEmail('nobody@example.com'), PasswordlessException::CODE_INVALID);
    }

    public function testEmailCodesAreBoundToTheirPurposeAndAddressAndDieAfterFiveWrongGuesses(): void
    {
        $graph = $this->polaris()->graph();
        $otp = $graph->get(EmailOtp::class);
        $ada = $this->user($graph, 'ada@example.com', verified: false);

        $otp->send('ada@example.com', EmailOtp::SIGN_IN);
        $code = $this->code();
        for ($i = 0; $i < 5; ++$i) {
            $this->refused(fn() => $otp->signIn('ada@example.com', '000000', $this->client), PasswordlessException::CODE_INVALID);
        }
        $this->refused(fn() => $otp->signIn('ada@example.com', $code, $this->client), PasswordlessException::CODE_INVALID, 'five wrong guesses kill the code');
        $otp->send('ada@example.com', EmailOtp::SIGN_IN);
        $this->refused(fn() => $otp->signIn('ada@example.com', $this->code(), $this->client), PasswordlessException::CODE_INVALID, 'a code sent again inherits the spent attempts');

        $this->clock->advance('+6 minutes');
        $otp->send('ada@example.com', EmailOtp::SIGN_IN);
        $code = $this->code();
        self::assertMatchesRegularExpression('/^\d{6}$/', $code);
        $this->refused(fn() => $otp->signIn('grace@example.com', $code, $this->client), PasswordlessException::CODE_INVALID, 'bound to its address');
        $this->refused(fn() => $otp->resetPassword('ada@example.com', $code, self::PASSWORD), PasswordlessException::CODE_INVALID, 'bound to its purpose');
        $data = $otp->signIn('ADA@example.com', $code, $this->client);
        self::assertSame([EmailOtp::AMR], $this->claims($graph, $data)['amr']);
        self::assertTrue($data['user']['email_verified'], 'proving the mailbox verifies it');
        self::assertNull($graph->users()->find($ada->id)?->passwordHash, 'a password set before anyone proved the mailbox goes');
        self::assertCount(1, $this->events->ofType(UserEmailVerified::class));
        $this->refused(fn() => $otp->signIn('ada@example.com', $code, $this->client), PasswordlessException::CODE_INVALID, 'once');
        $this->refused(fn() => $otp->signIn('nobody@example.com', '123456', $this->client), PasswordlessException::CODE_INVALID, 'an unknown address answers the same');

        $sent = count($this->mail->messages);
        $otp->send('ada@example.com', EmailOtp::VERIFY_EMAIL);
        self::assertCount($sent, $this->mail->messages, 'a verified address gets no verification code');
        $grace = $this->user($graph, 'grace@example.com', verified: false);
        $otp->send('grace@example.com', EmailOtp::VERIFY_EMAIL);
        $otp->verifyEmail('grace@example.com', $this->code());
        self::assertNotNull($graph->users()->find($grace->id)?->emailVerifiedAt);

        $session = $graph->get(Sessions::class)->open($ada, ['pwd'], $this->client);
        $otp->send('ada@example.com', EmailOtp::RESET_PASSWORD);
        $code = $this->code();
        $this->refused(fn() => $otp->resetPassword('ada@example.com', $code, 'short'), PasswordlessException::PASSWORD_INVALID);
        $otp->resetPassword('ada@example.com', $code, 'a brand new passphrase');
        self::assertCount(1, $this->events->ofType(PasswordChanged::class));
        self::assertNotNull($graph->database()->findOne('auth_refresh_tokens', ['user_id' => $ada->id, 'revoked_reason' => 'password_change']), 'every session ended');
        self::assertNotSame('', $session['refresh_token']);
        self::assertSame($ada->id, $graph->login()->login('ada@example.com', 'a brand new passphrase', $this->client)->userId);
        $this->refused(fn() => $otp->resetPassword('ada@example.com', $code, 'another new passphrase'), PasswordlessException::CODE_INVALID, 'once');
    }

    public function testCoresMfaGateHoldsUnlessTurnedOff(): void
    {
        $graph = $this->polaris()->graph();
        $ada = $this->user($graph, 'ada@example.com');
        self::factor($graph, $ada->id);

        $graph->get(EmailOtp::class)->send('ada@example.com', EmailOtp::SIGN_IN);
        $data = $graph->get(EmailOtp::class)->signIn('ada@example.com', $this->code(), $this->client);
        self::assertTrue($data['mfa_required']);
        self::assertNotEmpty($data['mfa_token']);
        self::assertSame('email', $data['factors'][0]['type']);
        self::assertArrayNotHasKey('access_token', $data);

        $this->mail->messages = [];
        $graph = $this->polaris(new PasswordlessPlugin(self::BASE, [self::DONE], respectMfa: false))->graph();
        $ada = $this->user($graph, 'ada@example.com');
        self::factor($graph, $ada->id);
        $graph->get(EmailOtp::class)->send('ada@example.com', EmailOtp::SIGN_IN);
        self::assertArrayHasKey('access_token', $graph->get(EmailOtp::class)->signIn('ada@example.com', $this->code(), $this->client));
    }

    public function testAPhoneIsAVerifiedSecondContactAndASignInIdentifierNeverASignUpOne(): void
    {
        $graph = $this->polaris()->graph();
        $phones = $graph->get(PhoneSignIn::class);
        $ada = $this->user($graph, 'ada@example.com');
        $grace = $this->user($graph, 'grace@example.com');

        $phones->add($ada->id, '+1 (555) 123-4567');
        self::assertSame('+15551234567', $this->sms->messages[0]->to);
        $code = $this->code($this->sms);
        $this->refused(fn() => $phones->confirm($grace->id, '+15551234567', $code), PasswordlessException::CODE_INVALID, 'only the user who asked');
        $this->refused(fn() => $phones->confirm($ada->id, '+15551234567', $code), PasswordlessException::CODE_INVALID, 'a refused confirmation spends the code');
        $phones->add($ada->id, '+15551234567');
        self::assertSame('+15551234567', $phones->confirm($ada->id, '+15551234567', $this->code($this->sms)));
        self::assertSame($ada->id, $graph->get(Phones::class)->owner('+15551234567'));
        self::assertSame('+15551234567', $graph->get(Phones::class)->forUser($ada->id));

        $phones->add($grace->id, '+15551234567');
        self::assertCount(2, $this->sms->messages, 'another account\'s number gets nothing, and the caller answers the same');
        $this->refused(fn() => $graph->get(Phones::class)->attach($grace->id, '+15551234567'), PasswordlessException::PHONE_TAKEN);
        $phones->send('+15550000000');
        self::assertCount(2, $this->sms->messages, 'an unknown number gets nothing and signs nobody up');
        $this->refused(fn() => $phones->signIn('+15550000000', '123456', $this->client), PasswordlessException::CODE_INVALID);
        $this->refused(fn() => $phones->send('not a number'), PasswordlessException::INVALID_INPUT);

        $phones->send('+1 555 123 4567');
        $code = $this->code($this->sms);
        $data = $phones->signIn('+15551234567', $code, $this->client);
        self::assertSame([$ada->id, [PhoneSignIn::AMR]], [$data['user']['id'], $this->claims($graph, $data)['amr']]);
        $this->refused(fn() => $phones->signIn('+15551234567', $code, $this->client), PasswordlessException::CODE_INVALID, 'once');
    }

    public function testAOneTimeTokenHandsASessionOverOnceWithItsAuthenticationFacts(): void
    {
        $graph = $this->polaris()->graph();
        $tokens = $graph->get(OneTimeTokens::class);
        $ada = $this->user($graph, 'ada@example.com');
        $issued = $graph->tokens()->issue(new SessionPrincipal($ada->id, null, [], [], true, true, ['pwd', 'otp'], 1760000000), $this->client);
        $access = $graph->tokenFactory()->fromTokenString($issued->accessToken);

        $generated = $tokens->generate($access);
        self::assertSame(180, $generated['expires_in']);
        $data = $tokens->verify($generated['token'], $this->client);
        $claims = $this->claims($graph, $data);
        self::assertSame([['pwd', 'otp'], true, 1760000000], [$claims['amr'], $claims['mfa'], $claims['auth_time']], 'inherited');
        self::assertNotSame($issued->sessionId, $claims['sid'], 'a new session');
        $this->refused(fn() => $tokens->verify($generated['token'], $this->client), PasswordlessException::TOKEN_INVALID, 'once');
        $generated = $tokens->generate($access);
        $this->clock->advance('+4 minutes');
        $this->refused(fn() => $tokens->verify($generated['token'], $this->client), PasswordlessException::TOKEN_INVALID, 'three minutes');

        $this->clock->advance('-4 minutes');
        $generated = $tokens->generate($access);
        $graph->tokens()->revokeFamily($issued->sessionId, 'logout');
        $this->refused(fn() => $tokens->verify($generated['token'], $this->client), PasswordlessException::TOKEN_INVALID, 'the token dies with its session');

        $impersonation = $graph->tokenFactory()->fromTokenString($graph->tokens()->mint(new SessionPrincipal($ada->id)));
        $this->refused(fn() => $tokens->generate($impersonation), PasswordlessException::SESSION_REQUIRED, 'no session behind the token');
        $this->refused(fn() => $tokens->generate($access), PasswordlessException::SESSION_REQUIRED, 'the session ended');
    }

    public function testSentinelGuardsTheNewRoutesThroughItsRoutesOption(): void
    {
        $sentinel = new SentinelPlugin(mode: SentinelPlugin::ENFORCE, routes: SentinelMiddleware::ROUTES + PasswordlessPlugin::SENTINEL_ROUTES + UsernamePlugin::SENTINEL_ROUTES + AnonymousPlugin::SENTINEL_ROUTES);
        $polaris = $this->polaris(null, [new AuditPlugin(), new AdminPlugin(), $sentinel, new UsernamePlugin(), new AnonymousPlugin()]);
        $graph = $polaris->graph();
        $graph->get(IpRules::class)->add('198.51.100.0/24', IpRule::BLOCK, 'scanner', 'test');
        $pipeline = new Pipeline($graph, new ResponseFactory());

        $guarded = ['/magic-link/send', '/email-otp/send', '/email-otp/verify', '/phone/send', '/phone/verify', '/username/sign-in', '/anonymous/sign-in'];
        foreach ($guarded as $path) {
            $request = (new ServerRequestFactory())->createServerRequest('POST', $path, ['REMOTE_ADDR' => '198.51.100.7'])->withParsedBody(['email' => 'ada@example.com', 'phone' => '+15551234567', 'code' => '123456', 'username' => 'ada', 'password' => 'x']);
            $response = $pipeline->handle($request);
            self::assertSame(403, $response->getStatusCode(), $path);
            self::assertSame('sentinel_blocked', json_decode((string) $response->getBody(), true)['error'] ?? null, $path);
        }
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/magic-link/send', ['REMOTE_ADDR' => '203.0.113.7'])->withParsedBody(['email' => 'ada@example.com']);
        self::assertSame(202, $pipeline->handle($request)->getStatusCode(), 'another address goes through');
    }

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, string $reason, string $message = ''): void
    {
        try {
            $call();
            self::fail($message === '' ? 'expected ' . $reason : $message);
        } catch (PasswordlessException $exception) {
            self::assertSame($reason, $exception->reason, $message);
        }
    }

    private function linkToken(): string
    {
        $link = (string) $this->mail->messages[array_key_last($this->mail->messages)]->vars['link'];
        self::assertStringStartsWith(self::BASE . '/magic-link/verify?token=', $link);

        return self::query($link)['token'];
    }

    private function code(?ArrayChannel $channel = null): string
    {
        $messages = ($channel ?? $this->mail)->messages;

        return (string) $messages[array_key_last($messages)]->vars['code'];
    }

    /**
     * @return array<string, string>
     */
    private static function query(string $url): array
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        /** @var array<string, string> $query */
        return $query;
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private function claims(Graph $graph, array $data): array
    {
        return $graph->tokenFactory()->fromTokenString((string) $data['access_token'])->getMetadata();
    }

    private function user(Graph $graph, string $email, bool $verified = true): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->passwordHash = $graph->passwordHasher()->hash(self::PASSWORD);
        $user->emailVerifiedAt = $verified ? $this->clock->now() : null;
        $user->createdAt = $user->updatedAt = $this->clock->now();
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    private static function factor(Graph $graph, string $userId): void
    {
        $now = new DateTimeImmutable(self::NOW);
        $graph->database()->insert('auth_mfa_factors', ['id' => 'factor-' . $userId, 'user_id' => $userId, 'type' => 'email', 'label' => null, 'secret_encrypted' => null, 'phone_e164' => null, 'email' => 'ada@example.com', 'is_default' => true, 'confirmed_at' => $now, 'last_used_at' => null, 'created_at' => $now, 'updated_at' => $now]);
    }

    /**
     * @return array<string, mixed>
     */
    private static function tables(Polaris $polaris): array
    {
        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[$model->table] = true;
        }

        return $tables;
    }

    /**
     * @param list<\Polaris\Contract\Plugin> $others registered before messaging and passwordless
     */
    private function polaris(?PasswordlessPlugin $plugin = null, array $others = [new AuditPlugin()]): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: $this->clock,
            dispatcher: $this->events,
            plugins: [...$others, new MessagingPlugin(channels: [$this->mail, $this->sms], caps: ['*' => [100, 600]]), $plugin ?? new PasswordlessPlugin(self::BASE, [self::DONE, self::OTHER])],
        ));
    }
}

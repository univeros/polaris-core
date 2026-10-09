<?php

declare(strict_types=1);

namespace Polaris\Passkey\Tests;

use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Event\MfaEnrolled;
use Polaris\Event\UserLoggedIn;
use Polaris\Exception\InvalidOtpException;
use Polaris\Identity\MfaChallengeResult;
use Polaris\Model\MfaFactor;
use Polaris\Model\User;
use Polaris\Passkey\Factor\PasskeyFactorType;
use Polaris\Passkey\Model\Passkey;
use Polaris\Passkey\PasskeyException;
use Polaris\Passkey\PasskeyPlugin;
use Polaris\Passkey\Passkeys;
use Polaris\Passkey\PasskeyService;
use Polaris\Passkey\Schema;
use Polaris\Passkey\Sessions;
use Polaris\Passkey\Settings;
use Polaris\Passkey\Tests\Support\SoftwareAuthenticator;
use Polaris\Passkey\WebauthnProtocol;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\ClientContext;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function array_column;
use function in_array;
use function str_repeat;

/**
 * The plugin wired through `Polaris::create()` and the ceremonies through the service with a software
 * authenticator: registration as a passkey and a core factor, discoverable sign-in with and without
 * user verification, the second factor through core's gate and step-up, renaming and removal in step
 * with core. Separate processes: the schema registry is static.
 */
#[CoversClass(PasskeyPlugin::class)]
#[CoversClass(Settings::class)]
#[CoversClass(PasskeyService::class)]
#[CoversClass(Passkeys::class)]
#[CoversClass(Sessions::class)]
#[CoversClass(WebauthnProtocol::class)]
#[CoversClass(PasskeyFactorType::class)]
#[CoversClass(PasskeyException::class)]
#[CoversClass(Passkey::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-09T10:00:00+00:00';
    private const string ORIGIN = 'https://app.example';
    private const string PASSWORD = 'correct horse battery staple';

    private MutableClock $clock;
    private RecordingEventDispatcher $events;
    private ClientContext $client;

    protected function setUp(): void
    {
        $this->clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $this->events = new RecordingEventDispatcher();
        $this->client = new ClientContext('203.0.113.7', 'ua/1');
    }

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();

        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[] = $model->table;
        }
        self::assertContains(Schema::PASSKEYS, $tables);
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (in_array('passkey', $spec->tags, true)) {
                $graph->endpoint($spec->class);
                $routes[] = $spec->method . ' ' . $spec->path . ' ' . $spec->auth . ($spec->stepUp ? ' step_up' : '');
            }
        }
        self::assertEqualsCanonicalizing(['POST /passkey/register/options bearer step_up', 'POST /passkey/register/verify bearer step_up', 'POST /passkey/authenticate/options public', 'POST /passkey/authenticate/verify public', 'GET /passkey/list bearer', 'PATCH /passkey/{id} bearer', 'DELETE /passkey/{id} bearer step_up'], $routes);
        self::assertSame(['app.example', ['https://app.example']], [PasskeyPlugin::of($graph)->settings()->rpId, PasskeyPlugin::of($graph)->settings()->origins]);
        self::assertInstanceOf(PasskeyFactorType::class, PasskeyPlugin::of($graph)->mfaFactorTypes($graph)[0]);
        self::assertSame([], (new PasskeyPlugin([self::ORIGIN], mfaFactor: false))->mfaFactorTypes($graph), 'no factor type when passkeys are not factors');
        self::assertSame(['localhost'], (new Settings(['https://app.example', 'http://localhost:8080/']))->insecureHosts());

        foreach ([static fn() => new Settings([]), static fn() => new Settings(['app.example']), static fn() => new Settings(['https://app.example/auth']), static fn() => new Settings([self::ORIGIN], userVerification: 'always'), static fn() => new Settings([self::ORIGIN], attachment: 'usb'), static fn() => new Settings(['http://app.example'])] as $invalid) {
            try {
                $invalid();
                self::fail('the settings are validated');
            } catch (LogicException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testRegistrationMakesAPasskeyAndAConfirmedCoreFactor(): void
    {
        $graph = $this->polaris()->graph();
        $service = $graph->get(PasskeyService::class);
        $ada = $this->user($graph, 'ada@example.com');
        $grace = $this->user($graph, 'grace@example.com');
        $authenticator = new SoftwareAuthenticator();

        $options = $service->registerOptions($ada);
        self::assertSame(['app.example', 'Polaris tests'], [$options['rp']['id'], $options['rp']['name']]);
        self::assertSame('ada@example.com', $options['user']['name']);
        self::assertSame('required', $options['authenticatorSelection']['residentKey'], 'discoverable by default');
        self::assertSame([], $options['excludeCredentials'] ?? []);
        $this->refused(fn() => $service->register($ada, $authenticator->create($options, 'https://evil.example'), 'MacBook'), PasskeyException::ORIGIN_MISMATCH);
        $this->refused(fn() => $service->register($grace, $authenticator->create($options, self::ORIGIN), 'MacBook'), PasskeyException::CHALLENGE_INVALID, 'another user\'s challenge, and it is spent');
        $this->refused(fn() => $service->register($ada, $authenticator->create($options, self::ORIGIN), 'MacBook'), PasskeyException::CHALLENGE_INVALID, 'once');
        $this->refused(fn() => $service->register($ada, '{"nope":true}', null), PasskeyException::INVALID_INPUT);

        $options = $service->registerOptions($ada);
        $registered = $service->register($ada, $authenticator->create($options, self::ORIGIN), ' MacBook ');
        $passkey = $registered['passkey'];
        self::assertSame(['MacBook', $authenticator->credentialIdEncoded(), ['internal', 'hybrid'], true, SoftwareAuthenticator::AAGUID], [$passkey->name, $passkey->credentialId, $passkey->transports, $passkey->backedUp, $passkey->aaguid]);
        self::assertNotEmpty($registered['recovery_codes'], 'the first factor');
        self::assertNotNull($passkey->factorId);
        $factor = $graph->database()->findOne('auth_mfa_factors', ['id' => $passkey->factorId]);
        self::assertSame([PasskeyFactorType::TYPE, 'MacBook', $ada->id], [$factor['type'] ?? null, $factor['label'] ?? null, $factor['user_id'] ?? null]);
        self::assertNotNull($factor['confirmed_at'] ?? null);
        self::assertCount(1, $this->events->ofType(MfaEnrolled::class));
        self::assertSame([PasskeyFactorType::TYPE], [$graph->mfaManagement()->list($ada->id)[0]->type], 'core lists it');

        $options = $service->registerOptions($ada);
        self::assertSame($authenticator->credentialIdEncoded(), $options['excludeCredentials'][0]['id'], 'the existing passkey is excluded');
        $this->refused(fn() => $service->register($ada, $authenticator->create($options, self::ORIGIN), null), PasskeyException::CREDENTIAL_INVALID, 'the same credential again');
        $second = $service->register($ada, (new SoftwareAuthenticator())->create($service->registerOptions($ada), self::ORIGIN), null);
        self::assertSame([PasskeyService::DEFAULT_NAME, []], [$second['passkey']->name, $second['recovery_codes']], 'a second factor answers no codes');
        self::assertCount(2, $service->list($ada->id));

        $plain = $this->polaris(new PasskeyPlugin([self::ORIGIN], rpName: 'Polaris tests', mfaFactor: false))->graph();
        $bob = $this->user($plain, 'bob@example.com');
        $registered = $plain->get(PasskeyService::class)->register($bob, (new SoftwareAuthenticator())->create($plain->get(PasskeyService::class)->registerOptions($bob), self::ORIGIN), null);
        self::assertSame([null, []], [$registered['passkey']->factorId, $registered['recovery_codes']], 'not a factor');
        self::assertSame([], $plain->mfaManagement()->list($bob->id));
    }

    public function testDiscoverableSignInOpensASessionAndTheGateAppliesWithoutUserVerification(): void
    {
        $graph = $this->polaris()->graph();
        $service = $graph->get(PasskeyService::class);
        $ada = $this->user($graph, 'ada@example.com');
        $authenticator = new SoftwareAuthenticator();
        $service->register($ada, $authenticator->create($service->registerOptions($ada), self::ORIGIN), 'MacBook');

        $options = $service->authenticateOptions();
        self::assertSame([[], 'app.example'], [$options['allowCredentials'], $options['rpId']], 'discoverable: no credential named');
        $this->refused(fn() => $service->authenticate($authenticator->get($options, 'https://evil.example', $ada->id), $this->client), PasskeyException::ORIGIN_MISMATCH);
        $this->refused(fn() => $service->authenticate((new SoftwareAuthenticator())->get($options, self::ORIGIN, $ada->id), $this->client), PasskeyException::CREDENTIAL_INVALID, 'an unknown credential, and the challenge is spent');
        $this->refused(fn() => $service->authenticate($authenticator->get($options, self::ORIGIN, $ada->id), $this->client), PasskeyException::CHALLENGE_INVALID, 'once');

        $assertion = $authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id, counter: 1);
        $data = $service->authenticate($assertion, $this->client);
        $claims = $graph->tokenFactory()->fromTokenString((string) $data['access_token'])->getMetadata();
        self::assertSame([[Sessions::AMR], true, $ada->id], [$claims['amr'], $claims['mfa'], $claims['sub']], 'user verification: the gate is passed');
        self::assertSame([Sessions::AMR], $this->events->ofType(UserLoggedIn::class)[0]->amr);
        self::assertSame(1, $service->list($ada->id)[0]->counter);
        self::assertNotNull($service->list($ada->id)[0]->lastUsedAt);
        $this->refused(fn() => $service->authenticate($assertion, $this->client), PasskeyException::CHALLENGE_INVALID, 'replayed');
        $this->refused(fn() => $service->authenticate($authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id, counter: 1), $this->client), PasskeyException::CREDENTIAL_INVALID, 'a counter that did not move: a cloned authenticator');

        $this->refused(fn() => $service->authenticate($authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id, userVerified: false, counter: 2), $this->client), PasskeyException::USER_VERIFICATION_REQUIRED, 'no user verification and the passkey is the only factor: it cannot be its own second factor');
        $now = $this->clock->now();
        $graph->database()->insert('auth_mfa_factors', ['id' => Uuid::v7()->toRfc4122(), 'user_id' => $ada->id, 'type' => 'totp', 'label' => 'App', 'secret_encrypted' => 'x', 'phone_e164' => null, 'email' => null, 'is_default' => false, 'confirmed_at' => $now, 'last_used_at' => null, 'created_at' => $now, 'updated_at' => $now]);
        $gated = $service->authenticate($authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id, userVerified: false, counter: 3), $this->client);
        self::assertTrue($gated['mfa_required'], 'no user verification: one factor, the gate applies');
        self::assertSame(['totp'], array_column($gated['factors'], 'type'), 'the signing passkey is not offered as its own second factor');
        self::assertArrayNotHasKey('access_token', $gated);

        $ada->status = User::STATUS_DISABLED;
        $graph->unitOfWork()->persist($ada);
        $graph->unitOfWork()->flush();
        $this->refused(fn() => $service->authenticate($authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id, counter: 4), $this->client), PasskeyException::ACCOUNT_DISABLED);
        $ada->status = User::STATUS_ACTIVE;
        $ada->emailVerifiedAt = null;
        $graph->unitOfWork()->persist($ada);
        $graph->unitOfWork()->flush();
        $this->refused(fn() => $service->authenticate($authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id, counter: 5), $this->client), PasskeyException::EMAIL_UNVERIFIED, 'core requires a verified email to sign in');

        $plain = $this->polaris(new PasskeyPlugin([self::ORIGIN], rpName: 'Polaris tests', mfaFactor: false))->graph();
        $bob = $this->user($plain, 'bob@example.com');
        $key = new SoftwareAuthenticator();
        $plain->get(PasskeyService::class)->register($bob, $key->create($plain->get(PasskeyService::class)->registerOptions($bob), self::ORIGIN), null);
        $data = $plain->get(PasskeyService::class)->authenticate($key->get($plain->get(PasskeyService::class)->authenticateOptions(), self::ORIGIN, $bob->id, userVerified: false), $this->client);
        $claims = $plain->tokenFactory()->fromTokenString((string) $data['access_token'])->getMetadata();
        self::assertSame([[Sessions::AMR], false], [$claims['amr'], $claims['mfa']], 'no factor to gate on: a one-factor session');
    }

    public function testAPasskeyIsASecondFactorThroughCoresGateAndStepUp(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();
        $this->events->listen(...$polaris->listeners());
        $service = $graph->get(PasskeyService::class);
        $ada = $this->user($graph, 'ada@example.com');
        $authenticator = new SoftwareAuthenticator();
        $passkey = $service->register($ada, $authenticator->create($service->registerOptions($ada), self::ORIGIN), 'MacBook')['passkey'];
        $other = new SoftwareAuthenticator();
        $service->register($ada, $other->create($service->registerOptions($ada), self::ORIGIN), 'Phone');

        $login = $graph->login()->login('ada@example.com', self::PASSWORD, $this->client);
        self::assertInstanceOf(MfaChallengeResult::class, $login, 'the password login hits the gate');
        self::assertSame((string) $passkey->factorId, $login->factors[0]->id);
        $assertion = $authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id);
        try {
            $graph->mfaLogin()->verify($ada->id, (string) $passkey->factorId, $other->get($service->authenticateOptions(), self::ORIGIN, $ada->id), $this->client);
            self::fail('another passkey than the factor\'s');
        } catch (InvalidOtpException) {
            self::addToAssertionCount(1);
        }
        $tokens = $graph->mfaLogin()->verify($ada->id, (string) $passkey->factorId, $assertion, $this->client);
        $claims = $graph->tokenFactory()->fromTokenString($tokens->accessToken)->getMetadata();
        self::assertSame([['pwd', 'otp'], true], [$claims['amr'], $claims['mfa']], 'core\'s post-MFA session');
        try {
            $graph->mfaLogin()->verify($ada->id, (string) $passkey->factorId, $assertion, $this->client);
            self::fail('replayed');
        } catch (InvalidOtpException) {
            self::addToAssertionCount(1);
        }
        $stepped = $graph->stepUp()->verify($ada->id, null, $tokens->sessionId, (string) $passkey->factorId, $authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id));
        self::assertNotSame('', $stepped);
        try {
            $graph->mfaLogin()->challenge($ada->id, (string) $passkey->factorId, $this->client);
            self::fail('a passkey has no sent challenge');
        } catch (InvalidOtpException) {
            self::addToAssertionCount(1);
        }

        $graph->mfaManagement()->remove($ada->id, (string) $passkey->factorId);
        self::assertNull($service->list($ada->id)[0]->factorId, 'removed under core\'s route: the passkey stays, detached');
        self::assertSame(['Phone'], [$graph->mfaManagement()->list($ada->id)[0]->label]);
        self::assertArrayHasKey('access_token', $service->authenticate($authenticator->get($service->authenticateOptions(), self::ORIGIN, $ada->id), $this->client), 'still a sign-in credential');
        $this->events->dispatch(new \Polaris\Event\UserDeleted($ada->id, 'admin'));
        self::assertSame([], $service->list($ada->id), 'an erased user leaves no passkey');
    }

    public function testRenameAndDeleteKeepCoreInStep(): void
    {
        $graph = $this->polaris()->graph();
        $service = $graph->get(PasskeyService::class);
        $ada = $this->user($graph, 'ada@example.com');
        $grace = $this->user($graph, 'grace@example.com');
        $passkey = $service->register($ada, (new SoftwareAuthenticator())->create($service->registerOptions($ada), self::ORIGIN), 'MacBook')['passkey'];

        $this->refused(fn() => $service->rename($grace->id, $passkey->id, 'Mine'), PasskeyException::NOT_FOUND, 'not grace\'s');
        $this->refused(fn() => $service->rename($ada->id, $passkey->id, str_repeat('x', 81)), PasskeyException::INVALID_INPUT);
        self::assertSame('Work laptop', $service->rename($ada->id, $passkey->id, 'Work laptop')->name);
        self::assertSame('Work laptop', $graph->mfaManagement()->list($ada->id)[0]->label, 'the factor follows');

        $ada->mfaEnforced = true;
        $graph->unitOfWork()->persist($ada);
        $graph->unitOfWork()->flush();
        $this->refused(fn() => $service->delete($ada->id, $passkey->id), PasskeyException::LAST_FACTOR);
        $ada->mfaEnforced = false;
        $graph->unitOfWork()->persist($ada);
        $graph->unitOfWork()->flush();
        $this->refused(fn() => $service->delete($grace->id, $passkey->id), PasskeyException::NOT_FOUND);
        $service->delete($ada->id, $passkey->id);
        self::assertSame([[], []], [$service->list($ada->id), $graph->mfaManagement()->list($ada->id)], 'the passkey and its factor are gone');
    }

    /**
     * @param callable(): mixed $call
     */
    private function refused(callable $call, string $reason, string $message = ''): void
    {
        try {
            $call();
            self::fail($message === '' ? 'expected ' . $reason : $message);
        } catch (PasskeyException $exception) {
            self::assertSame($reason, $exception->reason, $message . ' (' . $exception->detail . ')');
        }
    }

    private function user(Graph $graph, string $email): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->displayName = 'Ada';
        $user->passwordHash = $graph->passwordHasher()->hash(self::PASSWORD);
        $user->emailVerifiedAt = $this->clock->now();
        $user->createdAt = $user->updatedAt = $this->clock->now();
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    private function polaris(?PasskeyPlugin $plugin = null): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: $this->clock,
            dispatcher: $this->events,
            plugins: [$plugin ?? new PasskeyPlugin([self::ORIGIN], rpName: 'Polaris tests')],
        ));
    }
}

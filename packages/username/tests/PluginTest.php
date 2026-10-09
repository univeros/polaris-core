<?php

declare(strict_types=1);

namespace Polaris\Username\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Model\User;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\FrozenClock;
use Polaris\Tests\Support\TestKeys;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Attributes;
use Polaris\Token\SessionPrincipal;
use Polaris\Username\Http\SignInEndpoint;
use Polaris\Username\Http\UpdateEndpoint;
use Polaris\Username\Rules;
use Polaris\Username\Schema;
use Polaris\Username\UsernameException;
use Polaris\Username\UsernamePlugin;
use Polaris\Username\Usernames;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function in_array;
use function str_repeat;

/**
 * The plugin wired through `Polaris::create()`, the rules from configuration, and the sign-in through
 * core's password path: by username (any case) or email, the same refusal for an unknown name and a
 * wrong password, core's MFA gate. Separate processes: the schema registry is static.
 */
#[CoversClass(UsernamePlugin::class)]
#[CoversClass(Usernames::class)]
#[CoversClass(Rules::class)]
#[CoversClass(UsernameException::class)]
#[CoversClass(SignInEndpoint::class)]
#[CoversClass(UpdateEndpoint::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-09T10:00:00+00:00';
    private const string PASSWORD = 'correct horse battery staple';

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = self::polaris();
        $graph = $polaris->graph();

        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[] = $model->table;
        }
        self::assertContains(Schema::USERNAMES, $tables);
        $routes = [];
        foreach ($polaris->manifest()->endpoints() as $spec) {
            if (in_array('username', $spec->tags, true)) {
                $graph->endpoint($spec->class);
                $routes[] = $spec->method . ' ' . $spec->path . ' ' . $spec->auth;
            }
        }
        self::assertEqualsCanonicalizing(['POST /username/sign-in public', 'PATCH /username bearer'], $routes);
        self::assertSame(UsernamePlugin::ID, UsernamePlugin::of($graph)->id());
    }

    public function testTheRulesComeFromConfiguration(): void
    {
        $rules = new Rules();
        self::assertSame([], $rules->violations('ada.lovelace'));
        self::assertSame(['The username must be 3 to 30 characters long.'], $rules->violations('ab'));
        self::assertSame(['The username contains characters that are not allowed.'], $rules->violations('ada lovelace'));
        self::assertSame(['The username is reserved.'], $rules->violations('Admin'));

        $graph = self::polaris(new Rules(minLength: 5, maxLength: 8, pattern: '/^[a-z]+$/', reserved: ['grace']))->graph();
        $usernames = $graph->get(Usernames::class);
        self::assertSame('admin', $usernames->set('u1', 'admin')->username, 'the configured list replaces the default one');
        foreach (['abc', 'toolongname', 'Grace', 'ab_cd'] as $invalid) {
            try {
                $usernames->set('u2', $invalid);
                self::fail($invalid);
            } catch (UsernameException $exception) {
                self::assertSame(UsernameException::INVALID, $exception->reason, $invalid);
                self::assertNotEmpty($exception->errors);
            }
        }
        try {
            $usernames->set('u2', 'admin');
            self::fail('taken');
        } catch (UsernameException $exception) {
            self::assertSame([UsernameException::TAKEN, 'The username is taken.'], [$exception->reason, $exception->getMessage()]);
        }
        try {
            $usernames->set('u1', 'admin', 'other');
            self::fail('the display form is the same letters');
        } catch (UsernameException $exception) {
            self::assertSame(['The display username must be the username with another case.'], $exception->errors);
        }
    }

    public function testSignInByUsernameOrEmailGoesThroughCoresPasswordPath(): void
    {
        $graph = self::polaris()->graph();
        $ada = self::user($graph, 'ada@example.com');
        $update = $graph->endpoint(UpdateEndpoint::class);
        $signIn = $graph->endpoint(SignInEndpoint::class);

        self::assertSame(401, $update(new Input(['username' => 'Ada.L']))->status);
        $set = $update(new Input(['username' => 'ada.l', 'display_username' => 'Ada.L'], [Attributes::TOKEN => self::token($graph, $ada->id)]));
        self::assertSame(['data' => ['username' => 'ada.l', 'display_username' => 'Ada.L']], $set->body);
        self::assertSame(422, $update(new Input(['username' => 'no'], [Attributes::TOKEN => self::token($graph, $ada->id)]))->status);

        foreach (['ADA.L', 'ada@example.com'] as $identifier) {
            $result = $signIn(new Input(['username' => $identifier, 'password' => self::PASSWORD]));
            self::assertSame(200, $result->status, $identifier);
            $claims = $graph->tokenFactory()->fromTokenString((string) $result->body['data']['access_token'])->getMetadata();
            self::assertSame([$ada->id, ['pwd']], [$claims['sub'], $claims['amr']], 'core\'s password session');
        }
        $unknown = $signIn(new Input(['username' => 'nobody', 'password' => self::PASSWORD]));
        $wrong = $signIn(new Input(['username' => 'ada.l', 'password' => 'wrong password here']));
        self::assertSame([401, 401], [$unknown->status, $wrong->status]);
        self::assertSame($unknown->body, $wrong->body, 'an unknown username and a wrong password answer the same');
        self::problem($signIn(new Input(['username' => '', 'password' => 'x'])), 422, 'username_invalid_input');

        $now = new DateTimeImmutable(self::NOW);
        $graph->database()->insert('auth_mfa_factors', ['id' => Uuid::v7()->toRfc4122(), 'user_id' => $ada->id, 'type' => 'email', 'label' => null, 'secret_encrypted' => null, 'phone_e164' => null, 'email' => 'ada@example.com', 'is_default' => true, 'confirmed_at' => $now, 'last_used_at' => null, 'created_at' => $now, 'updated_at' => $now]);
        $gated = $signIn(new Input(['username' => 'ada.l', 'password' => self::PASSWORD]));
        self::assertTrue($gated->body['data']['mfa_required'], 'core\'s MFA gate');
        self::assertArrayNotHasKey('access_token', $gated->body['data']);

        $grace = self::user($graph, 'grace@example.com', verified: false);
        $graph->get(Usernames::class)->set($grace->id, 'grace');
        self::problem($signIn(new Input(['username' => 'grace', 'password' => self::PASSWORD])), 403, 'username_email_unverified');
        $grace->status = User::STATUS_DISABLED;
        $grace->emailVerifiedAt = $now;
        $graph->unitOfWork()->persist($grace);
        $graph->unitOfWork()->flush();
        self::problem($signIn(new Input(['username' => 'grace', 'password' => self::PASSWORD])), 403, 'username_account_disabled');
    }

    private static function problem(Result $result, int $status, string $error): void
    {
        self::assertSame([$status, $error, true], [$result->status, $result->body['error'] ?? null, $result->problem]);
    }

    private static function token(Graph $graph, string $userId): TokenInterface
    {
        return $graph->tokenFactory()->fromTokenString($graph->tokens()->mint(new SessionPrincipal($userId)));
    }

    private static function user(Graph $graph, string $email, bool $verified = true): User
    {
        $user = new User();
        $user->id = Uuid::v7()->toRfc4122();
        $user->email = $email;
        $user->passwordHash = $graph->passwordHasher()->hash(self::PASSWORD);
        $user->emailVerifiedAt = $verified ? new DateTimeImmutable(self::NOW) : null;
        $user->createdAt = $user->updatedAt = new DateTimeImmutable(self::NOW);
        $graph->unitOfWork()->persist($user);
        $graph->unitOfWork()->flush();

        return $user;
    }

    private static function polaris(Rules $rules = new Rules()): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
            database: new InMemoryAdapter(),
            clock: new FrozenClock(new DateTimeImmutable(self::NOW)),
            plugins: [new UsernamePlugin($rules)],
        ));
    }
}

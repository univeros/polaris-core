<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\CacheCounterStore;
use Polaris\Sentinel\Decision;
use Polaris\Sentinel\Policy;
use Polaris\Sentinel\Provider\BotVerifier;
use Polaris\Sentinel\Provider\BreachChecker;
use Polaris\Sentinel\Provider\FileDomainList;
use Polaris\Sentinel\Signal\Bot;
use Polaris\Sentinel\Signal\BreachedPassword;
use Polaris\Sentinel\Signal\CredentialStuffing;
use Polaris\Sentinel\Signal\DisposableEmail;
use Polaris\Sentinel\Signal\Velocity;
use Polaris\Sentinel\Verdict;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Support\InMemoryCache;
use Polaris\Tests\Support\FrozenClock;

/**
 * The signals that need no database, with fakes, and the policy that sums them.
 */
#[CoversClass(Velocity::class)]
#[CoversClass(CredentialStuffing::class)]
#[CoversClass(DisposableEmail::class)]
#[CoversClass(Bot::class)]
#[CoversClass(BreachedPassword::class)]
#[CoversClass(Policy::class)]
#[CoversClass(Decision::class)]
#[CoversClass(Attempt::class)]
#[CoversClass(CacheCounterStore::class)]
final class SignalsAndPolicyTest extends TestCase
{
    public function testVelocityScoresEachDimensionOverItsLimitAndResets(): void
    {
        $counters = new CacheCounterStore(new InMemoryCache(), FrozenClock::at('2026-09-11T10:00:00+00:00'));
        $velocity = new Velocity($counters, ['ip' => [2, 600], 'email' => [3, 600]]);
        $attempt = new Attempt(Attempt::SIGN_IN, 'Ada@Example.com ', '203.0.113.7', deviceId: 'dev-1');

        self::assertSame('ada@example.com', $attempt->email, 'normalised');
        self::assertSame(0, $velocity->evaluate($attempt)->score);
        self::assertSame(0, $velocity->evaluate($attempt)->score);
        $third = $velocity->evaluate($attempt);
        self::assertSame(50, $third->score, 'the address is over its limit');
        self::assertSame(['ip: 3 attempts in 600 s (limit 2)'], $third->reasons);
        $fourth = $velocity->evaluate($attempt);
        self::assertSame(100, $fourth->score, 'the address and the email');

        $velocity->reset('203.0.113.7');
        self::assertSame(50, $velocity->evaluate($attempt)->score, 'the email still counts');
        $velocity->reset('ada@example.com');
        self::assertSame(0, $velocity->evaluate($attempt)->score);
        self::assertSame(0, $velocity->evaluate(new Attempt(Attempt::SIGN_UP))->score, 'nothing to count');
    }

    public function testTheCounterStoreWindowsRollWithTheClock(): void
    {
        $clock = new MutableClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00'));
        $counters = new CacheCounterStore(new InMemoryCache(), $clock);
        self::assertSame(1, $counters->increment('k', 60));
        self::assertSame(2, $counters->increment('k', 60));
        self::assertSame(2, $counters->count('k', 60));
        $clock->advance('+2 minutes');
        self::assertSame(0, $counters->count('k', 60), 'a new window');
        self::assertSame(1, $counters->increment('k', 60));
        $counters->reset('k', 60);
        self::assertSame(0, $counters->count('k', 60));
    }

    public function testCredentialStuffingSeesManyAccountsAndFailuresFromOneAddress(): void
    {
        $cache = new InMemoryCache();
        $counters = new CacheCounterStore($cache, FrozenClock::at('2026-09-11T10:00:00+00:00'));
        $signal = new CredentialStuffing($counters, $cache, distinctEmails: 3, minAttempts: 4, failureRatio: 0.75);

        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_UP, 'a@example.com', '203.0.113.7'))->score, 'sign-ins only');
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_IN, 'a@example.com'))->score, 'no address, nothing to key on');
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_IN, 'a@example.com', '203.0.113.7'))->score);
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_IN, 'b@example.com', '203.0.113.7'))->score);
        $third = $signal->evaluate(new Attempt(Attempt::SIGN_IN, 'c@example.com', '203.0.113.7'));
        self::assertSame(60, $third->score);
        self::assertSame(['3 distinct accounts from one address in 600 s'], $third->reasons);

        $signal->failed('203.0.113.7');
        $signal->failed('203.0.113.7');
        $signal->failed('203.0.113.7');
        $signal->failed(null);
        $fourth = $signal->evaluate(new Attempt(Attempt::SIGN_IN, 'a@example.com', '203.0.113.7'));
        self::assertSame(120, $fourth->score, 'both reasons (the policy caps the sum)');
        self::assertSame('3 of 4 sign-ins from the address failed', $fourth->reasons[1]);

        $signal->reset('203.0.113.7');
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_IN, 'a@example.com', '203.0.113.7'))->score);
    }

    public function testDisposableEmailUsesTheBundledListPlusTheApplicationsOnSignUp(): void
    {
        $signal = new DisposableEmail(new FileDomainList(extra: ['Trash.Example']));

        self::assertSame(60, $signal->evaluate(new Attempt(Attempt::SIGN_UP, 'x@mailinator.com'))->score);
        self::assertSame(60, $signal->evaluate(new Attempt(Attempt::SIGN_UP, 'x@trash.example'))->score);
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_UP, 'x@example.com'))->score);
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_IN, 'x@mailinator.com'))->score, 'sign-ups only by default');
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_UP, 'not-an-email'))->score);
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_UP))->score);
    }

    public function testBotIsSilentWithoutATokenProvesAPassedChallengeOrScoresAGuess(): void
    {
        $verifier = new class implements BotVerifier {
            public function verify(string $token, ?string $ip): bool
            {
                return $token === 'good';
            }
        };
        $signal = new Bot($verifier);

        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_UP))->score);
        $passed = $signal->evaluate(new Attempt(Attempt::SIGN_UP, captchaToken: 'good'));
        self::assertSame([0, true], [$passed->score, $passed->passedChallenge]);
        $guess = $signal->evaluate(new Attempt(Attempt::SIGN_UP, captchaToken: 'bad'));
        self::assertSame([80, false, ['captcha token invalid']], [$guess->score, $guess->passedChallenge, $guess->reasons]);
    }

    public function testBreachedPasswordChecksNewPasswordsOnly(): void
    {
        $checker = new class implements BreachChecker {
            public function isBreached(string $password): bool
            {
                return $password === 'password1';
            }
        };
        $signal = new BreachedPassword($checker);

        self::assertSame(50, $signal->evaluate(new Attempt(Attempt::SIGN_UP, password: 'password1'))->score);
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_UP, password: 'correct horse battery staple'))->score);
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_IN, password: 'password1'))->score, 'a sign-in is not a new password');
        self::assertSame(0, $signal->evaluate(new Attempt(Attempt::SIGN_UP))->score);
    }

    public function testThePolicySumsCapsAndMapsTheScore(): void
    {
        $policy = new Policy();

        $quiet = $policy->decide([Verdict::silent('a'), Verdict::silent('b')], true);
        self::assertSame([Decision::ALLOW, 0, [], true], [$quiet->action, $quiet->score, $quiet->verdicts, $quiet->enforced]);

        $challenge = $policy->decide([new Verdict('a', 30, ['x']), new Verdict('b', 10, ['y'])], false);
        self::assertSame([Decision::CHALLENGE, 40, ['a', 'b'], ['x', 'y'], false], [$challenge->action, $challenge->score, $challenge->signals(), $challenge->reasons(), $challenge->enforced]);

        $block = $policy->decide([new Verdict('a', 70), new Verdict('b', 70)], true);
        self::assertSame([Decision::BLOCK, 100], [$block->action, $block->score]);

        $cleared = $policy->decide([new Verdict('ip_list', -100, ['allowed']), new Verdict('a', 70)], true);
        self::assertSame([Decision::ALLOW, 0, ['ip_list', 'a']], [$cleared->action, $cleared->score, $cleared->signals()]);

        $passed = $policy->decide([new Verdict('a', 60), new Verdict('bot', 0, ['captcha passed'], passedChallenge: true)], true);
        self::assertSame([Decision::ALLOW, 60, ['a', 'bot'], ['captcha passed']], [$passed->action, $passed->score, $passed->signals(), $passed->reasons()], 'a passed challenge turns a challenge into an allow and is listed; a block stays a block');
        self::assertSame(Decision::BLOCK, $policy->decide([new Verdict('a', 90), new Verdict('bot', 0, [], passedChallenge: true)], true)->action);

        $custom = new Policy(challengeAt: 20, blockAt: 50);
        self::assertSame(Decision::CHALLENGE, $custom->decide([new Verdict('a', 20)], true)->action);
        self::assertSame(Decision::BLOCK, $custom->decide([new Verdict('a', 50)], true)->action);
    }
}

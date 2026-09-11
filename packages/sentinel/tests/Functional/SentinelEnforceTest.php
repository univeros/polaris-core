<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Tests\Functional;

use Override;
use Polaris\Sentinel\SentinelPlugin;

use function array_column;

/**
 * Enforce mode with a captcha verifier: blocks and challenges are answered as problem documents, a
 * valid captcha token passes, the rules and unblock take effect at once.
 */
final class SentinelEnforceTest extends SentinelTestCase
{
    #[Override]
    protected static function sentinel(): SentinelPlugin
    {
        // Five attempts per email fire the velocity signal.
        return new SentinelPlugin(mode: SentinelPlugin::ENFORCE, verifier: self::verifier(), velocity: ['ip' => [100, 600], 'email' => [4, 600], 'device' => [100, 600]]);
    }

    public function testAttemptsAreBlockedChallengedAndCleared(): void
    {
        $challenge = $this->problem($this->send('POST', '/auth/register', ['email' => 'ada@mailinator.com', 'password' => self::PASSWORD]), 403, 'sentinel_challenge_required');
        self::assertSame('captcha', $challenge['challenge']);
        self::assertSame('Challenge required', $challenge['title']);
        $this->problem($this->send('POST', '/auth/register', ['email' => 'ada@mailinator.com', 'password' => self::PASSWORD, 'captcha_token' => 'bad']), 403, 'sentinel_blocked', 'a wrong token is a bot\'s guess');
        self::assertNotSame('', $this->login('ada@mailinator.com', captchaToken: 'good'), 'the retry with a valid token registers, and the sign-in is clean');

        $dave = ['email' => 'dave@example.com', 'password' => 'not the password'];
        for ($attempt = 1; $attempt <= 4; ++$attempt) {
            self::assertSame(401, $this->send('POST', '/auth/login', $dave)->getStatusCode(), "attempt $attempt");
        }
        $this->problem($this->send('POST', '/auth/login', $dave), 403, 'sentinel_challenge_required', 'the fifth attempt on the email is over the velocity limit');
        $owner = $this->operator();
        self::assertSame('unblocked', $this->json($this->send('POST', '/admin/sentinel/unblock', ['identifier' => 'dave@example.com'], $owner))['data']['status']);
        self::assertSame(401, $this->send('POST', '/auth/login', $dave)->getStatusCode(), 'the counters are cleared');

        $this->send('POST', '/admin/sentinel/ip-rules', ['cidr' => '198.51.100.0/24', 'action' => 'block', 'note' => 'scanner'], $owner);
        $blocked = $this->problem($this->send('POST', '/auth/login', ['email' => 'eve@example.com', 'password' => self::PASSWORD], ip: '198.51.100.9'), 403, 'sentinel_blocked');
        self::assertSame('The request was refused.', $blocked['detail'], 'the reason stays in the record');
        $this->send('POST', '/admin/sentinel/ip-rules', ['cidr' => self::IP, 'action' => 'allow', 'note' => 'office'], $owner);
        self::assertSame(202, $this->send('POST', '/auth/register', ['email' => 'carol@mailinator.com', 'password' => self::PASSWORD])->getStatusCode(), 'an allow rule clears the disposable domain');

        $decisions = $this->json($this->send('GET', '/admin/sentinel/decisions', accessToken: $owner))['data'];
        self::assertSame(['allow', 'block', 'challenge', 'allow', 'block', 'challenge'], array_column($decisions, 'action'));
        self::assertSame([true, true, true, true, true, true], array_column($decisions, 'enforced'));
        self::assertSame([['ip_list', 'disposable_email'], ['ip_list'], ['velocity'], ['disposable_email', 'bot'], ['disposable_email', 'bot'], ['disposable_email']], array_column($decisions, 'signals'));
        self::assertSame(['address blocked by rule 198.51.100.0/24'], $this->json($this->send('GET', '/admin/sentinel/decisions?ip=198.51.100.9', accessToken: $owner))['data'][0]['reasons']);
    }
}

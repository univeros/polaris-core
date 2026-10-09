<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Tests\Functional;

use function array_key_last;
use function count;

/**
 * The four methods end to end through the routes: each ends in core's login envelope, each secret works
 * once, and a known and an unknown identifier get the same answer.
 */
final class PasswordlessFlowTest extends PasswordlessTestCase
{
    public function testAMagicLinkSignsUpRedirectsWithACodeAndExchangesItOnce(): void
    {
        $this->problem($this->postJson('/magic-link/send', ['email' => 'not an email']), 422, 'passwordless_invalid_input');
        $this->problem($this->postJson('/magic-link/send', ['email' => 'ada@example.com', 'redirect_uri' => 'https://evil.example/']), 422, 'passwordless_redirect_not_allowed');
        $unknown = $this->postJson('/magic-link/send', ['email' => 'Ada@Example.com']);
        self::assertSame([202, ['data' => ['status' => 'sent']]], [$unknown->getStatusCode(), $this->json($unknown)]);
        $link = (string) self::$mail->messages[array_key_last(self::$mail->messages)]->vars['link'];
        self::assertStringStartsWith(self::BASE . '/magic-link/verify?token=', $link);

        $this->problem($this->get('/magic-link/verify'), 422, 'passwordless_invalid_input');
        $verify = $this->get('/magic-link/verify?token=' . self::param($link, 'token'));
        self::assertSame(302, $verify->getStatusCode());
        self::assertStringStartsWith(self::DONE . '?code=', $verify->getHeaderLine('Location'));
        $this->problem($this->get('/magic-link/verify?token=' . self::param($link, 'token')), 422, 'passwordless_token_invalid', 'a link works once');

        $code = self::param($verify->getHeaderLine('Location'), 'code');
        $this->problem($this->postJson('/magic-link/exchange', []), 422, 'passwordless_invalid_input');
        $this->problem($this->postJson('/magic-link/exchange', ['code' => 'nope']), 422, 'passwordless_token_invalid');
        $session = $this->json($this->postJson('/magic-link/exchange', ['code' => $code]))['data'];
        self::assertSame(['Bearer', 'ada@example.com', true], [$session['token_type'], $session['user']['email'], $session['user']['email_verified']]);
        self::assertSame(['magic_link'], $this->graph->tokenFactory()->fromTokenString((string) $session['access_token'])->getMetadata('amr'));
        $this->problem($this->postJson('/magic-link/exchange', ['code' => $code]), 422, 'passwordless_token_invalid', 'a code works once');
        self::assertSame('ada@example.com', $this->json($this->authedGet('/auth/me', (string) $session['access_token']))['data']['email']);

        $known = $this->postJson('/magic-link/send', ['email' => 'ada@example.com']);
        self::assertSame([$unknown->getStatusCode(), $this->json($unknown)], [$known->getStatusCode(), $this->json($known)], 'a known address gets the same answer');
    }

    public function testEmailCodesSignInVerifyTheEmailAndResetThePassword(): void
    {
        $this->postJson('/auth/register', ['email' => 'ada@example.com', 'password' => self::PASSWORD]);

        self::assertSame(202, $this->postJson('/email-otp/send', ['email' => 'ada@example.com', 'purpose' => 'verify-email'])->getStatusCode());
        $code = self::code(self::$mail);
        $this->problem($this->postJson('/email-otp/verify-email', ['email' => 'ada@example.com', 'code' => '000000']), 422, 'passwordless_code_invalid');
        self::assertSame(['status' => 'verified'], $this->json($this->postJson('/email-otp/verify-email', ['email' => 'ada@example.com', 'code' => $code]))['data']);
        $this->problem($this->postJson('/email-otp/verify-email', ['email' => 'ada@example.com', 'code' => $code]), 422, 'passwordless_code_invalid', 'once');

        $this->postJson('/email-otp/send', ['email' => 'ada@example.com']);
        $code = self::code(self::$mail);
        $this->problem($this->postJson('/email-otp/verify', ['email' => 'ada@example.com', 'code' => '000000']), 422, 'passwordless_code_invalid');
        $session = $this->json($this->postJson('/email-otp/verify', ['email' => 'ada@example.com', 'code' => $code]))['data'];
        self::assertSame(['email_otp'], $this->graph->tokenFactory()->fromTokenString((string) $session['access_token'])->getMetadata('amr'));
        $this->problem($this->postJson('/email-otp/verify', ['email' => 'ada@example.com', 'code' => $code]), 422, 'passwordless_code_invalid', 'once');

        $this->postJson('/email-otp/send', ['email' => 'ada@example.com', 'purpose' => 'reset-password']);
        $code = self::code(self::$mail);
        $this->problem($this->postJson('/email-otp/reset-password', ['email' => 'ada@example.com', 'code' => $code, 'password' => 'short']), 422, 'passwordless_password_invalid');
        self::assertSame(['status' => 'password_reset'], $this->json($this->postJson('/email-otp/reset-password', ['email' => 'ada@example.com', 'code' => $code, 'password' => 'a brand new passphrase']))['data']);
        self::assertSame(401, $this->postJson('/auth/token/refresh', ['refresh_token' => (string) $session['refresh_token']])->getStatusCode(), 'every session ended');
        self::assertSame(200, $this->postJson('/auth/login', ['email' => 'ada@example.com', 'password' => 'a brand new passphrase'])->getStatusCode());

        $this->problem($this->postJson('/email-otp/send', ['email' => 'ada@example.com', 'purpose' => 'unlock']), 422, 'passwordless_invalid_input');
        $sent = count(self::$mail->messages);
        self::assertSame(202, $this->postJson('/email-otp/send', ['email' => 'nobody@example.com', 'purpose' => 'reset-password'])->getStatusCode(), 'an unknown address gets the same answer');
        self::assertCount($sent, self::$mail->messages, 'and nothing');
        $this->problem($this->postJson('/email-otp/verify', ['email' => 'nobody@example.com', 'code' => '123456']), 422, 'passwordless_code_invalid', 'an unknown address answers as a wrong code');
    }

    public function testAVerifiedPhoneSignsItsOwnerIn(): void
    {
        $access = $this->login('ada@example.com');

        self::assertSame(401, $this->postJson('/phone/add', ['phone' => '+15551234567'])->getStatusCode());
        self::assertSame(202, $this->authedPostJson('/phone/add', ['phone' => '+1 (555) 123-4567'], $access)->getStatusCode());
        $code = self::code(self::$phone);
        $this->problem($this->authedPostJson('/phone/confirm', ['phone' => '+15551234567'], $access), 422, 'passwordless_invalid_input');
        self::assertSame(['phone' => '+15551234567', 'verified' => true], $this->json($this->authedPostJson('/phone/confirm', ['phone' => '+15551234567', 'code' => $code], $access))['data']);

        $known = $this->postJson('/phone/send', ['phone' => '+15551234567']);
        $code = self::code(self::$phone);
        $unknown = $this->postJson('/phone/send', ['phone' => '+15550000000']);
        self::assertSame([202, $this->json($known)], [$unknown->getStatusCode(), $this->json($unknown)], 'an unknown number gets the same answer');
        $this->problem($this->postJson('/phone/send', ['phone' => 'call me']), 422, 'passwordless_invalid_input');
        $this->problem($this->postJson('/phone/verify', ['phone' => '+15550000000', 'code' => $code]), 422, 'passwordless_code_invalid', 'an unknown number answers as a wrong code');
        $session = $this->json($this->postJson('/phone/verify', ['phone' => '+15551234567', 'code' => $code]))['data'];
        self::assertSame('ada@example.com', $session['user']['email']);
        self::assertSame(['phone'], $this->graph->tokenFactory()->fromTokenString((string) $session['access_token'])->getMetadata('amr'));
        $this->problem($this->postJson('/phone/verify', ['phone' => '+15551234567', 'code' => $code]), 422, 'passwordless_code_invalid', 'once');
    }

    public function testAOneTimeTokenHandsTheSessionToAnotherDeviceOnce(): void
    {
        $access = $this->login('ada@example.com');

        self::assertSame(401, $this->postJson('/one-time-token/generate', [])->getStatusCode());
        $generated = $this->json($this->authedPostJson('/one-time-token/generate', [], $access))['data'];
        self::assertSame(180, $generated['expires_in']);
        $this->problem($this->postJson('/one-time-token/verify', []), 422, 'passwordless_invalid_input');
        $session = $this->json($this->postJson('/one-time-token/verify', ['token' => (string) $generated['token']]))['data'];
        self::assertSame(['pwd'], $this->graph->tokenFactory()->fromTokenString((string) $session['access_token'])->getMetadata('amr'), 'the generating session\'s');
        self::assertSame('ada@example.com', $this->json($this->authedGet('/auth/me', (string) $session['access_token']))['data']['email']);
        $this->problem($this->postJson('/one-time-token/verify', ['token' => (string) $generated['token']]), 422, 'passwordless_token_invalid', 'once');
    }
}

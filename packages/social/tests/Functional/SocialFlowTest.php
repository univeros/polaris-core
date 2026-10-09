<?php

declare(strict_types=1);

namespace Polaris\Social\Tests\Functional;

use Polaris\Social\Tests\Support\RecordedProviders;

/**
 * The flows end to end through the routes against the recorded providers: Google signs up and signs in,
 * the accounts and a provider token from the session, GitHub linked from a session, unlinking and its
 * last-credential rule, Apple's form_post callback, One Tap, Microsoft and any other OAuth 2 server.
 * Each test keeps under core's per-IP budgets (ten callbacks and exchanges per five minutes).
 */
final class SocialFlowTest extends SocialTestCase
{
    public function testGoogleSignsUpThenSignsIn(): void
    {
        $this->problem($this->postJson('/social/nope/start', []), 404, 'social_provider_not_found');
        $this->problem($this->postJson('/social/google/start', ['redirect_uri' => 'https://evil.example/']), 422, 'social_redirect_not_allowed');
        $this->problem($this->get('/social/google/callback?code=good&state=unknown'), 422, 'social_state_invalid');
        $state = $this->start('google');
        $callback = $this->get('/social/google/callback?code=good&state=' . $state);
        self::assertSame(302, $callback->getStatusCode());
        self::assertStringStartsWith(self::DONE . '?code=', $callback->getHeaderLine('Location'));
        $this->problem($this->get('/social/google/callback?code=good&state=' . $state), 422, 'social_state_invalid', 'a state works once');
        $this->problem($this->postJson('/social/exchange', []), 422, 'social_invalid_input');
        $this->problem($this->postJson('/social/exchange', ['code' => 'nope']), 422, 'social_code_invalid');
        $code = self::param($callback->getHeaderLine('Location'), 'code');
        $session = $this->json($this->postJson('/social/exchange', ['code' => $code]))['data'];
        self::assertSame(['Bearer', 'ada@example.com', true], [$session['token_type'], $session['user']['email'], $session['user']['email_verified']]);
        self::assertSame(['social:google'], $this->graph->tokenFactory()->fromTokenString((string) $session['access_token'])->getMetadata('amr'));
        $this->problem($this->postJson('/social/exchange', ['code' => $code]), 422, 'social_code_invalid', 'once');
        self::assertSame('Ada Lovelace', $this->json($this->authedGet('/auth/me', (string) $session['access_token']))['data']['display_name'], 'signed up from the profile');

        $again = $this->json($this->postJson('/social/exchange', ['code' => self::param($this->get('/social/google/callback?code=good&state=' . $this->start('google'))->getHeaderLine('Location'), 'code')]))['data'];
        self::assertSame($session['user']['id'], $again['user']['id'], 'signed in by the linked account');
    }

    public function testTheAccountsAreManagedFromTheSession(): void
    {
        $session = $this->json($this->postJson('/social/exchange', ['code' => self::param($this->get('/social/google/callback?code=good&state=' . $this->start('google'))->getHeaderLine('Location'), 'code')]))['data'];
        $access = (string) $session['access_token'];

        self::assertSame(401, $this->get('/social/accounts')->getStatusCode());
        $accounts = $this->json($this->authedGet('/social/accounts', $access))['data'];
        self::assertSame(['google', RecordedProviders::GOOGLE_SUB, 'ada@example.com', true, 'Ada Lovelace'], [$accounts[0]['provider'], $accounts[0]['provider_account_id'], $accounts[0]['email'], $accounts[0]['email_verified'], $accounts[0]['profile']['name']]);
        self::assertArrayNotHasKey('access_token_enc', $accounts[0]);
        $token = $this->json($this->authedPostJson('/social/google/token', [], $access))['data'];
        self::assertSame(['ya29.a0AfB_byC-recorded-google-access-token', 'openid'], [$token['access_token'], $token['scopes'][0]]);
        $this->problem($this->authedPostJson('/social/github/token', [], $access), 404, 'social_not_linked');
        $this->problem($this->authedDelete('/social/google', $access), 409, 'social_last_credential', 'no password and one provider');

        self::assertSame(401, $this->postJson('/social/github/link', [])->getStatusCode());
        $state = $this->start('github', $access);
        $callback = $this->get('/social/github/callback?code=good&state=' . $state);
        self::assertSame(302, $callback->getStatusCode());
        $linked = $this->json($this->postJson('/social/exchange', ['code' => self::param($callback->getHeaderLine('Location'), 'code')]))['data'];
        self::assertSame(['linked', 'github', 'grace@example.com', true], [$linked['status'], $linked['account']['provider'], $linked['account']['email'], $linked['account']['email_verified']], 'the verified primary email from /user/emails; another email than the account\'s, allowed for GitHub');
        self::assertCount(2, $this->json($this->authedGet('/social/accounts', $access))['data']);
        self::assertSame(['status' => 'unlinked'], $this->json($this->authedDelete('/social/google', $access))['data'], 'GitHub remains');
        $this->problem($this->authedDelete('/social/google', $access), 404, 'social_not_linked');

        $again = $this->json($this->postJson('/social/exchange', ['code' => self::param($this->get('/social/google/callback?code=good&state=' . $this->start('google'))->getHeaderLine('Location'), 'code')]))['data'];
        self::assertSame($session['user']['id'], $again['user']['id'], 'Google is trusted: its verified email links the user again');
    }

    public function testAppleAnswersByFormPostOneTapVerifiesOfflineAndAnyOAuth2ServerSignsIn(): void
    {
        $state = $this->start('apple');
        $callback = $this->postJson('/social/apple/callback', ['code' => 'good', 'state' => $state, 'user' => '{"name":{"firstName":"Alan","lastName":"Turing"},"email":"alan@example.com"}']);
        self::assertSame(302, $callback->getStatusCode());
        $alan = $this->json($this->postJson('/social/exchange', ['code' => self::param($callback->getHeaderLine('Location'), 'code')]))['data'];
        self::assertSame('alan@example.com', $alan['user']['email']);
        self::assertSame('Alan Turing', $this->json($this->authedGet('/auth/me', (string) $alan['access_token']))['data']['display_name'], 'the name from the first callback');

        $this->problem($this->postJson('/social/google/one-tap', []), 422, 'social_invalid_input');
        $this->problem($this->postJson('/social/google/one-tap', ['credential' => 'not.a.jwt']), 403, 'social_provider_error');
        $ada = $this->json($this->postJson('/social/google/one-tap', ['credential' => RecordedProviders::mint('https://accounts.google.com', 'google-client', RecordedProviders::GOOGLE_SUB, 'ada@example.com', true, 'Ada Lovelace')]))['data'];
        self::assertSame(['ada@example.com', true], [$ada['user']['email'], $ada['user']['email_verified']]);

        $linus = $this->json($this->postJson('/social/exchange', ['code' => self::param($this->get('/social/microsoft/callback?code=good&state=' . $this->start('microsoft'))->getHeaderLine('Location'), 'code')]))['data'];
        self::assertSame('linus@example.com', $linus['user']['email']);
        $eve = $this->json($this->postJson('/social/exchange', ['code' => self::param($this->get('/social/acme/callback?code=good&state=' . $this->start('acme'))->getHeaderLine('Location'), 'code')]))['data'];
        self::assertSame(['eve@example.com', ['social:acme']], [$eve['user']['email'], $this->graph->tokenFactory()->fromTokenString((string) $eve['access_token'])->getMetadata('amr')], 'GenericOAuth from a definition');
    }

    public function testAnUntrustedProviderLinksOnlyFromASession(): void
    {
        $grace = $this->login('grace@example.com');

        $this->problem($this->get('/social/github/callback?code=good&state=' . $this->start('github')), 409, 'social_account_exists', 'GitHub is not trusted to link an existing email by itself');
        $state = $this->start('github', $grace);
        $linked = $this->json($this->postJson('/social/exchange', ['code' => self::param($this->get('/social/github/callback?code=good&state=' . $state)->getHeaderLine('Location'), 'code')]))['data'];
        self::assertSame(['linked', 'github'], [$linked['status'], $linked['account']['provider']]);
        $signedIn = $this->json($this->postJson('/social/exchange', ['code' => self::param($this->get('/social/github/callback?code=good&state=' . $this->start('github'))->getHeaderLine('Location'), 'code')]))['data'];
        self::assertSame('grace@example.com', $signedIn['user']['email'], 'linked: it signs in now');
        self::assertSame(['status' => 'unlinked'], $this->json($this->authedDelete('/social/github', $grace))['data'], 'a password remains');
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Passkey\Tests\Functional;

use Polaris\Passkey\Tests\Support\SoftwareAuthenticator;

use function json_decode;

/**
 * The ceremonies end to end through the routes: registration (a passkey and a core factor with recovery
 * codes), the list, discoverable sign-in with conditional-UI options, the passkey as the second factor
 * of a password login through core's `/auth/mfa/verify`, renaming, removal.
 */
final class PasskeyFlowTest extends PasskeyTestCase
{
    public function testAPasskeyRegistersSignsInAndIsASecondFactor(): void
    {
        $access = $this->login('ada@example.com');
        $authenticator = new SoftwareAuthenticator();

        self::assertSame(401, $this->postJson('/passkey/register/options', [])->getStatusCode());
        $options = $this->json($this->authedPostJson('/passkey/register/options', [], $access))['data'];
        self::assertSame(['auth.polaris.test', 'Polaris tests'], [$options['rp']['id'], $options['rp']['name']]);
        $this->problem($this->authedPostJson('/passkey/register/verify', [], $access), 422, 'passkey_invalid_input');
        $this->problem($this->authedPostJson('/passkey/register/verify', ['credential' => json_decode($authenticator->create($options, 'https://evil.example'), true)], $access), 403, 'passkey_origin_mismatch');
        $registered = $this->authedPostJson('/passkey/register/verify', ['credential' => json_decode($authenticator->create($options, self::ORIGIN), true), 'name' => 'MacBook'], $access);
        self::assertSame(201, $registered->getStatusCode(), 'an origin mismatch is refused before the challenge is spent');
        $this->problem($this->authedPostJson('/passkey/register/verify', ['credential' => json_decode($authenticator->create($options, self::ORIGIN), true)], $access), 422, 'passkey_challenge_invalid', 'once');
        $passkey = $this->json($registered)['data']['passkey'];
        self::assertSame(['MacBook', true], [$passkey['name'], $passkey['backed_up']]);
        self::assertNotEmpty($this->json($registered)['data']['recovery_codes'], 'the first factor');
        self::assertSame('passkey', $this->json($this->authedGet('/auth/mfa/factors', $access))['data']['factors'][0]['type'], 'core lists the factor');

        $list = $this->json($this->authedGet('/passkey/list', $access))['data'];
        self::assertSame([$passkey['id']], [$list[0]['id']]);
        self::assertSame('Work laptop', $this->json($this->authedPatch('/passkey/' . $passkey['id'], ['name' => 'Work laptop'], $access))['data']['name']);

        $request = $this->json($this->postJson('/passkey/authenticate/options', []))['data'];
        self::assertSame([], $request['allowCredentials'], 'conditional UI: discoverable');
        $this->problem($this->postJson('/passkey/authenticate/verify', ['credential' => 'garbage']), 422, 'passkey_invalid_input');
        $this->problem($this->postJson('/passkey/authenticate/verify', ['credential' => json_decode((new SoftwareAuthenticator())->get($request, self::ORIGIN, (string) $list[0]['id']), true)]), 422, 'passkey_credential_invalid', 'an unknown credential');
        $request = $this->json($this->postJson('/passkey/authenticate/options', []))['data'];
        $me = $this->json($this->authedGet('/auth/me', $access))['data'];
        $signedIn = $this->json($this->postJson('/passkey/authenticate/verify', ['credential' => json_decode($authenticator->get($request, self::ORIGIN, (string) $me['id'], counter: 1), true)]))['data'];
        self::assertSame(['Bearer', 'ada@example.com'], [$signedIn['token_type'], $signedIn['user']['email']]);
        self::assertSame([['passkey'], true], [$this->graph->tokenFactory()->fromTokenString((string) $signedIn['access_token'])->getMetadata('amr'), $this->graph->tokenFactory()->fromTokenString((string) $signedIn['access_token'])->getMetadata('mfa')]);
        $this->problem($this->postJson('/passkey/authenticate/verify', ['credential' => json_decode($authenticator->get($request, self::ORIGIN, (string) $me['id'], counter: 2), true)]), 422, 'passkey_challenge_invalid', 'once');

        $gate = $this->json($this->postJson('/auth/login', ['email' => 'ada@example.com', 'password' => self::PASSWORD]))['data'];
        self::assertTrue($gate['mfa_required'], 'the passkey gates the password login');
        $request = $this->json($this->postJson('/passkey/authenticate/options', []))['data'];
        self::assertSame(422, $this->authedPostJson('/auth/mfa/verify', ['factor_id' => $passkey['factor_id'], 'code' => (new SoftwareAuthenticator())->get($request, self::ORIGIN, (string) $me['id'])], (string) $gate['mfa_token'])->getStatusCode(), 'another passkey is a wrong code');
        $request = $this->json($this->postJson('/passkey/authenticate/options', []))['data'];
        $verified = $this->authedPostJson('/auth/mfa/verify', ['factor_id' => $passkey['factor_id'], 'code' => $authenticator->get($request, self::ORIGIN, (string) $me['id'], counter: 2)], (string) $gate['mfa_token']);
        self::assertSame(200, $verified->getStatusCode());
        $session = $this->json($verified)['data'];
        self::assertSame(['pwd', 'otp'], $this->graph->tokenFactory()->fromTokenString((string) $session['access_token'])->getMetadata('amr'), 'core\'s post-MFA session');

        $request = $this->json($this->postJson('/passkey/authenticate/options', []))['data'];
        self::assertSame(200, $this->authedPostJson('/auth/mfa/step-up', ['factor_id' => $passkey['factor_id'], 'code' => $authenticator->get($request, self::ORIGIN, (string) $me['id'], counter: 3)], (string) $session['access_token'])->getStatusCode(), 'step-up with the passkey');
        $this->problem($this->authedDelete('/passkey/' . $me['id'], (string) $session['access_token']), 404, 'passkey_not_found');
        self::assertSame(['status' => 'deleted'], $this->json($this->authedDelete('/passkey/' . $passkey['id'], (string) $session['access_token']))['data'], 'a fresh post-MFA session passes the step-up gate');
        self::assertSame([], $this->json($this->authedGet('/passkey/list', (string) $session['access_token']))['data']);
        self::assertSame([], $this->json($this->authedGet('/auth/mfa/factors', (string) $session['access_token']))['data']['factors'], 'the factor went with it');
    }
}

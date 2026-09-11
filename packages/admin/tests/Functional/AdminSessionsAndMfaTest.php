<?php

declare(strict_types=1);

namespace Polaris\Admin\Tests\Functional;

use OTPHP\TOTP;
use Polaris\Admin\Principal\Role;

use function array_column;

final class AdminSessionsAndMfaTest extends AdminTestCase
{
    public function testSessionsAreListedAndRevokedBySupport(): void
    {
        $this->login('ada@example.com');
        $this->login('ada@example.com');
        $adaId = $this->userId('ada@example.com');
        $support = $this->key(Role::Support);
        $viewer = $this->key(Role::Viewer);

        $sessions = $this->json($this->authedGet('/admin/users/' . $adaId . '/sessions', $viewer))['data'];
        self::assertCount(2, $sessions);
        self::assertSame([false, false], array_column($sessions, 'current'));
        $this->problem($this->authedDelete('/admin/users/' . $adaId . '/sessions/' . $sessions[0]['id'], $viewer), 403, 'admin_forbidden');
        self::assertSame('revoked', $this->json($this->authedDelete('/admin/users/' . $adaId . '/sessions/' . $sessions[0]['id'], $support))['data']['status']);
        $this->problem($this->authedDelete('/admin/users/' . $adaId . '/sessions/no-such-session', $support), 404, 'admin_not_found');
        self::assertCount(1, $this->json($this->authedGet('/admin/users/' . $adaId . '/sessions', $support))['data']);

        $this->login('ada@example.com');
        $all = $this->json($this->authedDelete('/admin/users/' . $adaId . '/sessions', $support))['data'];
        self::assertSame(['status' => 'revoked', 'count' => 3], $all, 'the families of the user, the already revoked one included, as core\'s logout-all counts them');
        self::assertSame([], $this->json($this->authedGet('/admin/users/' . $adaId . '/sessions', $support))['data']);
        $this->problem($this->authedGet('/admin/users/nobody/sessions', $support), 404, 'admin_not_found');
    }

    public function testMfaFactorsAreListedRemovedAndReset(): void
    {
        $ada = $this->login('ada@example.com');
        $adaId = $this->userId('ada@example.com');
        $owner = $this->operator();
        $this->enrol($ada);

        $factors = $this->json($this->authedGet('/admin/users/' . $adaId . '/mfa', $owner))['data'];
        self::assertCount(1, $factors);
        self::assertSame('totp', $factors[0]['type']);
        self::assertNotNull($factors[0]['confirmed_at']);
        self::assertArrayNotHasKey('secret', $factors[0]);

        $this->problem($this->authedDelete('/admin/users/' . $adaId . '/mfa/nope', $owner), 404, 'admin_not_found');
        self::assertSame('removed', $this->json($this->authedDelete('/admin/users/' . $adaId . '/mfa/' . $factors[0]['id'], $owner))['data']['status']);
        self::assertSame([], $this->json($this->authedGet('/admin/users/' . $adaId . '/mfa', $owner))['data']);

        $this->enrol($ada);
        self::assertSame(1, $this->adapter->count('auth_recovery_codes', ['user_id' => $adaId]) > 0 ? 1 : 0, 'recovery codes were issued');
        self::assertSame(['status' => 'reset', 'factors' => 1], $this->json($this->authedDelete('/admin/users/' . $adaId . '/mfa', $owner))['data']);
        self::assertSame(0, $this->adapter->count('auth_recovery_codes', ['user_id' => $adaId]));
        self::assertSame([], $this->json($this->authedGet('/admin/users/' . $adaId . '/mfa', $owner))['data']);
        self::assertSame(['admin.mfa_reset', 'admin.mfa_factor_removed'], array_column($this->json($this->authedGet('/admin/audit?names=admin.mfa_reset,admin.mfa_factor_removed', $owner))['data'], 'name'));
    }

    private function enrol(string $access): void
    {
        $enroll = $this->json($this->authedPostJson('/auth/mfa/totp/enroll', [], $access))['data'];
        $totp = TOTP::createFromSecret($enroll['secret']);
        $totp->setPeriod(30);
        $totp->setDigits(6);
        $totp->setDigest('sha1');
        self::assertSame(200, $this->authedPostJson('/auth/mfa/totp/confirm', ['factor_id' => $enroll['factor_id'], 'code' => $totp->now()], $access)->getStatusCode());
    }
}

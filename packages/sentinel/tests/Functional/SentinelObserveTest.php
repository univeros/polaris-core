<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Tests\Functional;

use Override;
use Polaris\Admin\Principal\Role;
use Polaris\Sentinel\SentinelPlugin;

use function array_column;

/**
 * Observe mode: every attempt goes through, what a signal said is recorded and listed; the operators'
 * rules and unblock.
 */
final class SentinelObserveTest extends SentinelTestCase
{
    #[Override]
    protected static function sentinel(): SentinelPlugin
    {
        // Three attempts per email fire the velocity signal.
        return new SentinelPlugin(mode: SentinelPlugin::OBSERVE, velocity: ['ip' => [100, 600], 'email' => [2, 600], 'device' => [100, 600]]);
    }

    public function testDecisionsAreRecordedNotEnforcedAndListedForOperators(): void
    {
        self::assertNotSame('', $this->login('ada@mailinator.com'), 'a disposable domain is let through in observe mode');
        self::assertSame(202, $this->send('POST', '/auth/password/forgot', ['email' => 'ada@mailinator.com'])->getStatusCode(), 'the third attempt on the email is over the velocity limit, still let through');
        $owner = $this->operator();

        $this->problem($this->send('GET', '/admin/sentinel/decisions'), 401, 'admin_unauthorized');
        $this->problem($this->send('GET', '/admin/sentinel/decisions?action=nope', accessToken: $owner), 422, 'admin_invalid_input');
        $this->problem($this->send('GET', '/admin/sentinel/decisions?limit=0', accessToken: $owner), 422, 'admin_invalid_input');
        $decisions = $this->json($this->send('GET', '/admin/sentinel/decisions', accessToken: $owner))['data'];
        self::assertSame(['password_reset', 'sign_up'], array_column($decisions, 'kind'), 'newest first; silence is not recorded');
        self::assertSame([['velocity'], ['disposable_email']], array_column($decisions, 'signals'));
        self::assertSame(['challenge', 'challenge'], array_column($decisions, 'action'));
        self::assertSame([false, false], array_column($decisions, 'enforced'));
        self::assertSame(['ada@mailinator.com', self::IP, ['email: 3 attempts in 600 s (limit 2)']], [$decisions[0]['email'], $decisions[0]['ip'], $decisions[0]['reasons']]);
        self::assertCount(1, $this->json($this->send('GET', '/admin/sentinel/decisions?action=challenge&limit=1', accessToken: $owner))['data']);
        self::assertSame([], $this->json($this->send('GET', '/admin/sentinel/decisions?action=block', accessToken: $owner))['data']);
        self::assertSame([], $this->json($this->send('GET', '/admin/sentinel/decisions?email=bob@example.com', accessToken: $owner))['data']);
        self::assertCount(2, $this->json($this->send('GET', '/admin/sentinel/decisions?email=Ada@mailinator.com&ip=' . self::IP, accessToken: $owner))['data']);
        self::assertSame(['sentinel.evaluated', 'sentinel.evaluated'], array_column($this->json($this->send('GET', '/admin/audit?names=sentinel.evaluated', accessToken: $owner))['data'], 'name'));
    }

    public function testIpRulesNeedAnOwnerAndUnblockASupportRole(): void
    {
        $owner = $this->operator();
        $viewer = $this->key(Role::Viewer);
        $support = $this->key(Role::Support);

        $this->problem($this->send('POST', '/admin/sentinel/ip-rules', ['cidr' => 'nowhere', 'action' => 'block'], $owner), 422, 'admin_invalid_input');
        $this->problem($this->send('POST', '/admin/sentinel/ip-rules', ['cidr' => '198.51.100.0/24', 'action' => 'deny'], $owner), 422, 'admin_invalid_input');
        $this->problem($this->send('POST', '/admin/sentinel/ip-rules', ['cidr' => '198.51.100.0/24', 'action' => 'block', 'note' => str_repeat('n', 256)], $owner), 422, 'admin_invalid_input');
        $this->problem($this->send('POST', '/admin/sentinel/ip-rules', ['cidr' => '198.51.100.0/24', 'action' => 'block'], $support), 403, 'admin_forbidden');
        $rule = $this->json($this->send('POST', '/admin/sentinel/ip-rules', ['cidr' => '198.51.100.0/24', 'action' => 'block', 'note' => 'scanner'], $owner))['data'];
        self::assertSame(['198.51.100.0/24', 'block', 'scanner'], [$rule['cidr'], $rule['action'], $rule['note']]);
        $allow = $this->json($this->send('POST', '/admin/sentinel/ip-rules', ['cidr' => '2001:db8::/32', 'action' => 'allow'], $owner))['data'];
        self::assertNull($allow['note']);

        $this->problem($this->send('GET', '/admin/sentinel/ip-rules'), 401, 'admin_unauthorized');
        self::assertSame([$rule['id'], $allow['id']], array_column($this->json($this->send('GET', '/admin/sentinel/ip-rules', accessToken: $viewer))['data'], 'id'), 'in creation order; a viewer reads');

        $this->problem($this->send('POST', '/admin/sentinel/unblock', ['identifier' => 'ada@example.com'], $viewer), 403, 'admin_forbidden');
        $this->problem($this->send('POST', '/admin/sentinel/unblock', ['identifier' => ' '], $support), 422, 'admin_invalid_input');
        self::assertSame(['status' => 'unblocked', 'identifier' => 'ada@example.com'], $this->json($this->send('POST', '/admin/sentinel/unblock', ['identifier' => 'Ada@Example.com'], $support))['data']);

        $this->problem($this->send('DELETE', '/admin/sentinel/ip-rules/' . $rule['id'], accessToken: $support), 403, 'admin_forbidden');
        self::assertSame('deleted', $this->json($this->send('DELETE', '/admin/sentinel/ip-rules/' . $rule['id'], accessToken: $owner))['data']['status']);
        $this->problem($this->send('DELETE', '/admin/sentinel/ip-rules/' . $rule['id'], accessToken: $owner), 404, 'admin_not_found');
        self::assertSame([$allow['id']], array_column($this->json($this->send('GET', '/admin/sentinel/ip-rules', accessToken: $owner))['data'], 'id'));
        $audited = $this->json($this->send('GET', '/admin/audit?names=sentinel.ip_rule_created,sentinel.ip_rule_deleted,sentinel.unblocked', accessToken: $owner))['data'];
        self::assertSame(['sentinel.ip_rule_deleted', 'sentinel.unblocked', 'sentinel.ip_rule_created', 'sentinel.ip_rule_created'], array_column($audited, 'name'));
        self::assertSame(['api_key', 'email'], [$audited[1]['actor_type'], $audited[1]['data']['kind']]);
        self::assertArrayNotHasKey('identifier', $audited[1]['data'], 'the identifier is hashed in the audit store');
    }
}

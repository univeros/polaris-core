<?php

declare(strict_types=1);

namespace Polaris\Agents\Tests\Functional;

use Polaris\Admin\Grants as AdminGrants;
use Polaris\Admin\Principal\Role;
use Polaris\Agents\AuditNames;
use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Schema;
use Polaris\Agents\Tests\Support\AgentKey;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Symfony\Component\Uid\Uuid;

use function array_column;
use function array_combine;
use function array_filter;
use function array_values;
use function count;
use function ksort;
use function str_repeat;
use function strtolower;

/**
 * WP4 acceptance 3 and 4: register (a user's and an organization's agent), enrol through a host, request
 * grants and approve them by each method (device code, CIBA, in-app) or by policy, execute with a
 * handler, spend a budget to exhaustion, verify the receipt chain and detect a tampered receipt, and
 * revoke: the chain is sealed and nothing runs after.
 */
final class AgentsLifecycleTest extends AgentsTestCase
{
    public function testRegisterAndEnrollAgentsAndHosts(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $key = new AgentKey();

        // A user's autonomous agent with a secret, asking for a low-risk capability: approved by policy.
        $own = $this->registerAgent($session, ['name' => 'Deploy bot', 'mode' => 'autonomous', 'capabilities' => ['members.list']]);
        self::assertStringStartsWith('pcs_', (string) $own['client_secret']);
        self::assertSame(['user', $userId, $orgId, 'active', 'auto', 100, null], [$own['owner_type'], $own['owner_id'], $own['organization_id'], $own['grants'][0]['status'], $own['grants'][0]['approved_via'], $own['grants'][0]['budget']['total'], $own['approval']]);

        // An organization's delegated agent with a key (Ada holds org.update in her active organization).
        $org = $this->registerAgent($session, ['name' => 'Reviewer', 'auth' => 'private_key_jwt', 'jwk' => $key->jwk(), 'organization_id' => $orgId]);
        self::assertSame(['organization', $orgId, $userId, $key->kid(), 'ES256'], [$org['owner_type'], $org['owner_id'], $org['created_by'], $org['public_jwk']['kid'], $org['public_jwk']['alg']]);
        self::assertArrayNotHasKey('client_secret', $org);
        $this->agentsProblem($this->authedPostJson('/agents/register', ['name' => 'X', 'mode' => 'delegated', 'auth' => 'client_secret', 'organization_id' => Uuid::v7()->toRfc4122()], $session), 403, 'forbidden', message: 'another organization');
        $this->agentsProblem($this->authedPostJson('/agents/register', ['name' => 'X', 'mode' => 'autonomous', 'auth' => 'delegated_token'], $session), 422, 'invalid_input', message: 'an autonomous agent needs a credential');

        // The owner's lists.
        $listed = $this->json($this->authedGet('/agents', $session))['data'];
        self::assertSame([$own['id'], $org['id']], array_column($listed, 'id'));
        self::assertSame('members.list', $this->json($this->authedGet('/agents/' . $own['id'], $session))['data']['grants'][0]['capability']);
        $this->agentsProblem($this->authedGet('/agents/' . Uuid::v7()->toRfc4122(), $session), 404, 'not_found');

        // A host enrols an agent under Ada with the host's default capabilities, approved by policy.
        $host = $this->json($this->authedPostJson('/agents/hosts', ['name' => 'Laptop', 'default_capabilities' => ['members.list']], $session))['data'];
        self::assertStringStartsWith('peh_', (string) $host['enrollment_token']);
        self::assertSame([$host['id']], array_column($this->json($this->authedGet('/agents/hosts', $session))['data'], 'id'));
        $enrolKey = new AgentKey('EdDSA');
        $enrolled = $this->json($this->bearer($host['enrollment_token'], 'POST', '/agents/enroll', ['name' => 'Claude Code', 'mode' => 'delegated', 'auth' => 'private_key_jwt', 'jwk' => $enrolKey->jwk()]))['data'];
        self::assertSame([$host['id'], 'user', $userId, $orgId, 'active', 'EdDSA'], [$enrolled['host_id'], $enrolled['owner_type'], $enrolled['owner_id'], $enrolled['organization_id'], $enrolled['grants'][0]['status'], $enrolled['public_jwk']['alg']]);
        $this->agentsProblem($this->bearer('peh_' . str_repeat('x', 43), 'POST', '/agents/enroll', ['name' => 'X', 'mode' => 'delegated', 'auth' => 'client_secret']), 401, 'unauthorized');
        $this->agentsProblem($this->bearer($host['enrollment_token'], 'POST', '/agents/enroll', ['name' => '', 'mode' => 'delegated', 'auth' => 'client_secret']), 422, 'invalid_input');

        // The enrolled agent reads its session with a signed JWT; the host is revoked and enrols no more.
        $me = $this->json($this->signed($enrolKey, $enrolled['id'], 'GET', '/agents/session'))['data'];
        self::assertSame([$enrolled['id'], 'delegated', ['type' => 'user', 'id' => $userId], 'Laptop', 'jwt', 'members.list'], [$me['agent']['id'], $me['mode'], $me['owner'], $me['host']['name'], $me['authenticated_via'], $me['grants'][0]['capability']]);
        self::assertSame('revoked', $this->json($this->authedDelete('/agents/hosts/' . $host['id'], $session))['data']['status']);
        $this->agentsProblem($this->bearer($host['enrollment_token'], 'POST', '/agents/enroll', ['name' => 'X', 'mode' => 'delegated', 'auth' => 'client_secret']), 401, 'unauthorized', message: 'a revoked host');

        // Suspend and resume.
        self::assertSame('suspended', $this->json($this->authedPostJson('/agents/' . $enrolled['id'] . '/suspend', [], $session))['data']['status']);
        $this->agentsProblem($this->signed($enrolKey, $enrolled['id'], 'GET', '/agents/session'), 401, 'agent_inactive', 'agent_suspended');
        $this->agentsProblem($this->authedPostJson('/agents/' . $enrolled['id'] . '/suspend', [], $session), 409, 'conflict');
        self::assertSame('active', $this->json($this->authedPostJson('/agents/' . $enrolled['id'] . '/resume', [], $session))['data']['status']);
        self::assertSame(200, $this->signed($enrolKey, $enrolled['id'], 'GET', '/agents/session')->getStatusCode());

        // The discovery document and the capabilities, with the agent's grant status.
        $discovery = $this->json($this->get('/.well-known/agent-configuration'));
        self::assertSame(['1.0-draft', 'Polaris test', self::BASE . '/agents/execute', self::BASE . '/oauth2/token'], [$discovery['version'], $discovery['provider_name'], $discovery['default_location'], $discovery['token_endpoint']]);
        self::assertStringContainsString('max-age=3600', $this->get('/.well-known/agent-configuration')->getHeaderLine('Cache-Control'));
        $capabilities = $this->json($this->signed($enrolKey, $enrolled['id'], 'GET', '/agents/capabilities'))['data']['capabilities'];
        self::assertSame(['members.list' => 'active', 'org.rename' => 'none', 'audit.export' => 'none', 'credits.spend' => 'none', 'invite' => 'none'], array_combine(array_column($capabilities, 'name'), array_column($capabilities, 'grant_status')));
        self::assertSame(self::LOCATION, $capabilities[4]['location']);
        self::assertArrayNotHasKey('grant_status', $this->json($this->get('/agents/capabilities'))['data']['capabilities'][0]);

        $names = [];
        foreach ($this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::REGISTERED, AuditNames::ENROLLED, AuditNames::SUSPENDED, AuditNames::RESUMED]))->events as $event) {
            $names[$event->name] = $event->actorType;
        }
        ksort($names);
        self::assertSame(['agent.enrolled' => 'agent', 'agent.registered' => 'user', 'agent.resumed' => 'user', 'agent.suspended' => 'user'], $names);
    }

    public function testGrantsAreApprovedByEachMethodOrByPolicy(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $key = new AgentKey();
        $agent = $this->registerAgent($session, ['name' => 'Reviewer', 'auth' => 'private_key_jwt', 'jwk' => $key->jwk()]);
        $id = (string) $agent['id'];

        // Device authorization: the agent asks, a person types the code on the host's page and approves.
        $asked = $this->json($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => ['org.rename', 'members.list'], 'preferred_method' => 'device_authorization', 'reason' => 'Rename on request']));
        self::assertSame($id, $asked['agent_id']);
        $byName = array_combine(array_column($asked['agent_capability_grants'], 'capability'), $asked['agent_capability_grants']);
        self::assertSame(['pending', 'active'], [$byName['org.rename']['status'], $byName['members.list']['status']], 'high waits for a person, low is approved by policy');
        $approval = $asked['approval'];
        self::assertSame(['device_authorization', 'step_up', self::APPROVE, self::APPROVE . '?user_code=' . $approval['user_code'], 600, 5], [$approval['method'], $approval['strength'], $approval['verification_uri'], $approval['verification_uri_complete'], $approval['expires_in'], $approval['interval']]);
        self::assertMatchesRegularExpression('/^[BCDFGHJKMNPQRSTVWXZ]{4}-[BCDFGHJKMNPQRSTVWXZ]{4}$/', $approval['user_code']);
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => ['nope']]), 404, 'capability_not_found');
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => [['name' => 'audit.export', 'constraints' => ['format' => ['between' => [1, 2]]]]]]), 400, 'unknown_constraint_operator');
        $shown = $this->json($this->authedGet('/agents/approvals/code?user_code=' . strtolower($approval['user_code']), $session))['data'];
        self::assertSame([$id, 'org.rename', 'step_up'], [$shown['agent']['id'], $shown['grants'][0]['capability'], $shown['strength']]);
        $this->agentsProblem($this->authedGet('/agents/approvals/code?user_code=ZZZZ-ZZZZ', $session), 404, 'not_found');
        $decided = $this->json($this->authedPostJson('/agents/approvals/' . $approval['id'] . '/decide', ['decision' => 'approve', 'constraints' => ['name' => ['pattern' => 'Acme.*']]], $session))['data'];
        self::assertSame(['approved', 'active', 'device_authorization', ['name' => ['pattern' => 'Acme.*']]], [$decided['status'], $decided['grants'][0]['status'], $decided['grants'][0]['approved_via'], $decided['grants'][0]['constraints']]);
        $this->agentsProblem($this->authedPostJson('/agents/approvals/' . $approval['id'] . '/decide', ['decision' => 'approve'], $session), 409, 'conflict', message: 'decided once');

        // CIBA: the agent asks with a binding message; the host pushes it from the event; the person decides.
        $ciba = $this->json($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => [['name' => 'credits.spend', 'constraints' => ['amount' => ['max' => 50], 'budget' => ['amount' => 100, 'field' => 'amount']]]], 'preferred_method' => 'ciba', 'binding_message' => 'Spend credits?']));
        self::assertSame(['ciba', 'Spend credits?', 'session'], [$ciba['approval']['method'], $ciba['approval']['binding_message'], $ciba['approval']['strength']]);
        $requested = array_values(array_filter($this->events->ofType(AgentEvent::class), static fn(AgentEvent $event): bool => $event->name === AuditNames::GRANT_REQUESTED && $event->data['method'] === 'ciba'));
        self::assertSame(['Spend credits?', $id, 'agent', $userId], [$requested[0]->data['binding_message'], $requested[0]->agentId, $requested[0]->actorType, $requested[0]->subjectId]);
        self::assertSame('active', $this->json($this->authedPostJson('/agents/approvals/' . $ciba['approval']['id'] . '/decide', ['decision' => 'approve'], $session))['data']['grants'][0]['status']);

        // In-app: the owner's own client lists the pending approvals and denies one.
        $inApp = $this->json($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => ['audit.export'], 'preferred_method' => 'in_app']));
        $pending = $this->json($this->authedGet('/agents/approvals', $session))['data'];
        self::assertSame([$inApp['approval']['id'], 'audit.export', 'in_app'], [$pending[0]['id'], $pending[0]['grants'][0]['capability'], $pending[0]['method']]);
        self::assertSame('denied', $this->json($this->authedPostJson('/agents/approvals/' . $inApp['approval']['id'] . '/decide', ['decision' => 'deny'], $session))['data']['grants'][0]['status']);
        self::assertSame([], $this->json($this->authedGet('/agents/approvals', $session))['data']);
        $this->agentsProblem($this->authedPostJson('/agents/approvals/' . $inApp['approval']['id'] . '/decide', ['decision' => 'maybe'], $session), 422, 'invalid_input');

        // The owner revokes a grant; the agent sees it at once.
        $session2 = $this->json($this->signed($key, $id, 'GET', '/agents/session'))['data']['grants'];
        self::assertSame(['org.rename' => 'active', 'members.list' => 'active', 'credits.spend' => 'active', 'audit.export' => 'denied'], array_combine(array_column($session2, 'capability'), array_column($session2, 'status')));
        self::assertSame('revoked', $this->json($this->authedDelete('/agents/grants/' . $byName['members.list']['id'], $session))['data']['status']);
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []]), 403, 'capability_not_granted');
        $this->agentsProblem($this->authedDelete('/agents/grants/' . $byName['members.list']['id'], $session), 409, 'conflict');

        $how = [];
        foreach ($this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::GRANT_APPROVED, AuditNames::GRANT_DENIED, AuditNames::GRANT_REVOKED]))->events as $event) {
            $how[] = $event->name . ':' . ($event->data['how'] ?? '-') . ':' . $event->actorType;
        }
        self::assertSame(['agent.grant.revoked:-:user', 'agent.grant.denied:in_app:user', 'agent.grant.approved:ciba:user', 'agent.grant.approved:device_authorization:user', 'agent.grant.approved:auto:system'], $how, 'newest first');
    }

    public function testExecutionBudgetsReceiptsAndTheKillSwitch(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $key = new AgentKey();
        $agent = $this->registerAgent($session, ['name' => 'Spender', 'auth' => 'private_key_jwt', 'jwk' => $key->jwk(), 'capabilities' => ['members.list']]);
        $id = (string) $agent['id'];
        $asked = $this->json($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => [['name' => 'credits.spend', 'constraints' => ['amount' => ['max' => 50], 'budget' => ['amount' => 100, 'field' => 'amount']]]], 'preferred_method' => 'in_app']));
        $this->authedPostJson('/agents/approvals/' . $asked['approval']['id'] . '/decide', ['decision' => 'approve'], $session);

        // A handler runs, the receipt is answered; `input` is an alias of `arguments`.
        $first = $this->json($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []]));
        self::assertSame([['members' => 1, 'agent' => $id], 1], [$first['data'], $first['receipt']['seq']]);
        self::assertSame(2, $this->json($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'members.list', 'input' => []]))['receipt']['seq']);
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => ['extra' => 1]]), 422, 'invalid_arguments', message: 'the input schema');
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'org.rename', 'arguments' => ['name' => 'X']]), 403, 'capability_not_granted');
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []], ['capabilities' => ['credits.spend']]), 403, 'capability_not_granted', message: 'the JWT restricts the capabilities');
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'nope', 'arguments' => []]), 404, 'capability_not_found');

        // Constraints and the amount budget: 100 credits, at most 50 a call.
        $violated = $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'credits.spend', 'arguments' => ['amount' => 60]]), 403, 'constraint_violated');
        self::assertSame([['field' => 'amount', 'constraint' => 'max', 'actual' => 60]], $violated['violations']);
        self::assertSame(['spent' => 40], $this->json($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'credits.spend', 'arguments' => ['amount' => 40]]))['data']);
        $this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'credits.spend', 'arguments' => ['amount' => 40]]);
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'credits.spend', 'arguments' => ['amount' => 40]]), 403, 'budget_exhausted', message: '20 left');
        self::assertSame(['spent' => 20], $this->json($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'credits.spend', 'arguments' => ['amount' => 20]]))['data']);
        $grants = $this->json($this->signed($key, $id, 'GET', '/agents/session'))['data']['grants'];
        $spend = array_values(array_filter($grants, static fn(array $grant): bool => $grant['capability'] === 'credits.spend'))[0];
        self::assertSame(['exhausted', 0], [$spend['status'], $spend['budget']['remaining']]);
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'credits.spend', 'arguments' => ['amount' => 1]]), 403, 'capability_not_granted', message: 'an exhausted grant is no grant');

        // The chain: five receipts, each verifying and linked to the previous; a tampered one fails.
        $chain = $this->json($this->authedGet('/agents/' . $id . '/receipts', $session))['data'];
        self::assertSame([1, 2, 3, 4, 5], array_column($chain, 'seq'));
        self::assertSame([null, $chain[0]['hash'], $chain[1]['hash']], [$chain[0]['prev_hash'], $chain[1]['prev_hash'], $chain[2]['prev_hash']]);
        self::assertSame([100, 60, 20, 0], [$chain[2]['budget_before'], $chain[2]['budget_after'], $chain[3]['budget_after'], $chain[4]['budget_after']]);
        foreach ($chain as $receipt) {
            self::assertTrue($this->json($this->authedGet('/agents/receipts/' . $receipt['id'] . '/verify', $session))['data']['valid'], 'receipt ' . $receipt['seq']);
        }
        self::assertSame(1, $this->adapter->update(Schema::RECEIPTS, ['id' => $chain[2]['id']], ['budget_after' => 99]));
        $tampered = $this->json($this->authedGet('/agents/receipts/' . $chain[2]['id'] . '/verify', $session))['data'];
        self::assertSame([false, ['hash' => false, 'signature' => false, 'chain' => true]], [$tampered['valid'], $tampered['checks']]);
        self::assertSame(['hash' => true, 'signature' => true, 'chain' => false], $this->json($this->authedGet('/agents/receipts/' . $chain[3]['id'] . '/verify', $session))['data']['checks'], 'the next receipt no longer links to it');
        $this->adapter->update(Schema::RECEIPTS, ['id' => $chain[2]['id']], ['budget_after' => 60]);
        $page = $this->json($this->authedGet('/agents/' . $id . '/receipts?after=2&limit=2', $session));
        self::assertSame([[3, 4], 4, true], [array_column($page['data'], 'seq'), $page['next_cursor'], $page['has_more']]);

        // The kill switch: tokens, grants and approvals end, the chain is sealed, nothing runs after.
        $pendingAgain = $this->json($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => ['audit.export'], 'preferred_method' => 'in_app']));
        $revoked = $this->json($this->authedPostJson('/agents/' . $id . '/revoke', [], $session))['data'];
        self::assertSame(['revoked', 'sealed', 6, null, $chain[4]['hash']], [$revoked['status'], $revoked['sealed_receipt']['outcome'], $revoked['sealed_receipt']['seq'], $revoked['sealed_receipt']['capability'], $revoked['sealed_receipt']['prev_hash']]);
        self::assertNotNull($revoked['sealed_at']);
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []]), 401, 'agent_inactive', 'agent_revoked');
        $this->agentsProblem($this->authedPostJson('/agents/' . $id . '/resume', [], $session), 409, 'conflict', message: 'revoked for good');
        $this->agentsProblem($this->authedPostJson('/agents/' . $id . '/revoke', [], $session), 409, 'conflict');
        self::assertSame([], $this->json($this->authedGet('/agents/approvals', $session))['data'], 'pending approvals are cancelled');
        $after = $this->json($this->authedGet('/agents/' . $id, $session))['data'];
        self::assertSame(['revoked', 'exhausted', 'revoked'], array_column($after['grants'], 'status'), 'live and pending grants are revoked; the exhausted one stays as it was');
        self::assertSame(6, count($this->json($this->authedGet('/agents/' . $id . '/receipts', $session))['data']));
        self::assertTrue($this->json($this->authedGet('/agents/receipts/' . $revoked['sealed_receipt']['id'] . '/verify', $session))['data']['valid']);

        // Operators see every agent and may pull the switch too.
        $this->graph->get(AdminGrants::class)->grant($userId, Role::Owner);
        $other = $this->registerAgent($session, ['name' => 'Other']);
        self::assertSame([$id, $other['id']], array_column($this->json($this->authedGet('/admin/agents', $session))['data'], 'id'));
        self::assertSame('revoked', $this->json($this->authedPostJson('/admin/agents/' . $other['id'] . '/revoke', [], $session))['data']['status']);
        self::assertSame(409, $this->authedPostJson('/admin/agents/' . $other['id'] . '/revoke', [], $session)->getStatusCode());

        $names = [];
        foreach ($this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::EXECUTED, AuditNames::EXECUTION_DENIED, AuditNames::GRANT_EXHAUSTED, AuditNames::REVOKED, AuditNames::RECEIPT_SEALED]))->events as $event) {
            $names[$event->name] = ($names[$event->name] ?? 0) + 1;
            self::assertSame($event->name === AuditNames::REVOKED ? 'user' : ($event->name === AuditNames::RECEIPT_SEALED ? 'system' : 'agent'), $event->actorType, $event->name);
        }
        ksort($names);
        self::assertSame(['agent.executed' => 5, 'agent.execution_denied' => 7, 'agent.grant.exhausted' => 1, 'agent.receipt.sealed' => 2, 'agent.revoked' => 2], $names);
    }
}

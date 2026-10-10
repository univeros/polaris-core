<?php

declare(strict_types=1);

namespace Polaris\Agents\Tests\Functional;

use Laminas\Diactoros\Response\JsonResponse;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\AuditNames;
use Polaris\Agents\Http\AgentRequestMiddleware;
use Polaris\Agents\Model\Grant;
use Polaris\Agents\Model\Receipt;
use Polaris\Agents\Receipts;
use Polaris\Agents\Schema;
use Polaris\Agents\Tests\Support\AgentKey;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Exchange;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function array_column;
use function array_map;
use function count;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * WP4 acceptance 5 and the location half of acceptance 3: a delegated agent exchanges the user's session
 * for a token carrying `act`, calls a core route and executes a capability, and the audit store records
 * the agent as the actor and the user as the subject; an autonomous agent's client-credentials token acts
 * as its owner within its grants and is refused outside them; a capability with a location cannot be
 * reached without passing `AgentRequestMiddleware`.
 */
final class AgentTokensTest extends AgentsTestCase
{
    public function testADelegatedAgentActsForTheUserThroughTokenExchange(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $key = new AgentKey();
        $agent = $this->registerAgent($session, ['name' => 'Reviewer', 'auth' => 'private_key_jwt', 'jwk' => $key->jwk(), 'organization_id' => $orgId, 'capabilities' => ['members.list']]);
        $id = (string) $agent['id'];
        $assertion = static fn(): array => ['client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion' => $key->assertion($id, self::BASE . '/oauth2/token')];

        // The exchange: the agent's client, authenticated by its key, exchanges Ada's session within its grants.
        $exchanged = $this->json($this->form('/oauth2/token', [...$assertion(), 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $session, 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN, 'scope' => 'members.read']));
        self::assertArrayHasKey('access_token', $exchanged, json_encode($exchanged, JSON_THROW_ON_ERROR));
        $claims = self::claims($exchanged['access_token']);
        self::assertSame([$userId, $orgId, $id, ['sub' => $id, 'client_id' => $id]], [$claims['sub'], $claims['org'], $claims['client_id'], $claims['act']]);
        $this->problem($this->form('/oauth2/token', [...$assertion(), 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $session, 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN, 'scope' => 'org.update']), 400, 'invalid_scope', 'beyond the grants');
        $this->problem($this->form('/oauth2/token', [...$assertion(), 'grant_type' => 'client_credentials']), 400, 'unauthorized_client', 'a delegated agent cannot act as itself');

        // The token on a core route (the agent principal: Ada, delegated members.read) and on an execution.
        $token = (string) $exchanged['access_token'];
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId . '/members', $token)->getStatusCode());
        self::assertSame(403, $this->authedGet('/orgs/' . $orgId . '/roles', $token)->getStatusCode(), 'roles.read was not granted');
        self::assertSame($userId, $this->json($this->authedGet('/auth/me', $token))['data']['id']);
        $executed = $this->json($this->bearer($token, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []]));
        self::assertSame(['members' => 1, 'agent' => $id], $executed['data']);
        self::assertSame('oauth', $this->json($this->bearer($token, 'GET', '/agents/session'))['data']['authenticated_via']);
        self::assertTrue($this->json($this->bearer($token, 'GET', '/agents/receipts/' . $executed['receipt']['id'] . '/verify'))['data']['valid'], 'the agent verifies its own receipt');
        $this->agentsProblem($this->bearer($token, 'POST', '/agents/execute', ['capability' => 'org.rename', 'arguments' => ['name' => 'X']]), 403, 'capability_not_granted');
        $this->agentsProblem($this->bearer('not-a-token', 'POST', '/agents/execute', ['capability' => 'members.list']), 401, 'invalid_jwt');
        $this->agentsProblem($this->handle($this->request('POST', '/agents/execute')->withParsedBody(['capability' => 'members.list'])), 401, 'unauthorized');

        // The audit store: the execution by the agent, for Ada.
        $events = $this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::EXECUTED]))->events;
        self::assertCount(1, $events);
        self::assertSame(['agent', $id, $userId, $orgId, 'members.list'], [$events[0]->actorType, $events[0]->actorId, $events[0]->subjectId, $events[0]->organizationId, $events[0]->data['capability']]);

        // A revoked grant takes effect at the next request; a revoked agent's token is dead.
        $grantId = $this->json($this->authedGet('/agents/' . $id, $session))['data']['grants'][0]['id'];
        $this->authedDelete('/agents/grants/' . $grantId, $session);
        self::assertSame(403, $this->authedGet('/orgs/' . $orgId . '/members', $token)->getStatusCode());
        $this->authedPostJson('/agents/' . $id . '/revoke', [], $session);
        self::assertSame(401, $this->authedGet('/auth/me', $token)->getStatusCode(), 'the token was revoked with the agent');
        $this->problem($this->form('/oauth2/token', [...$assertion(), 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $session, 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN]), 401, 'invalid_client', 'the client is disabled');
    }

    public function testAnAutonomousAgentActsAsItsOwnerWithinItsGrants(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $agent = $this->registerAgent($session, ['name' => 'Deploy bot', 'mode' => 'autonomous', 'capabilities' => ['members.list']]);
        $auth = ['Authorization' => self::basic($agent['id'], $agent['client_secret'])];

        $own = $this->json($this->form('/oauth2/token', ['grant_type' => 'client_credentials', 'scope' => 'members.read'], $auth));
        self::assertSame($agent['id'], self::claims($own['access_token'])['sub']);
        $this->problem($this->form('/oauth2/token', ['grant_type' => 'client_credentials', 'scope' => 'org.update'], $auth), 400, 'invalid_scope', 'the client scopes follow the grants');
        $token = (string) $own['access_token'];

        // As Ada, in Acme, within members.read; refused outside it and on a permissionless write (the delegation rule).
        self::assertSame($userId, $this->json($this->authedGet('/auth/me', $token))['data']['id']);
        self::assertSame(200, $this->authedGet('/orgs/' . $orgId . '/members', $token)->getStatusCode());
        self::assertSame(403, $this->authedGet('/orgs/' . $orgId . '/roles', $token)->getStatusCode());
        self::assertSame(403, $this->authedPostJson('/orgs', ['name' => 'Evil'], $token)->getStatusCode(), 'a permissionless write');
        self::assertSame(403, $this->authedPostJson('/agents/register', ['name' => 'Child', 'mode' => 'delegated', 'auth' => 'client_secret'], $token)->getStatusCode(), 'an agent never registers an agent');
        $executed = $this->json($this->bearer($token, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []]));
        self::assertSame(1, $executed['receipt']['seq']);

        // Suspended: every token is refused; resumed: they work again; a revoked grant takes effect at once.
        $this->authedPostJson('/agents/' . $agent['id'] . '/suspend', [], $session);
        $this->agentsProblem($this->authedGet('/auth/me', $token), 401, 'agent_inactive', 'agent_suspended');
        $this->authedPostJson('/agents/' . $agent['id'] . '/resume', [], $session);
        self::assertSame(200, $this->authedGet('/auth/me', $token)->getStatusCode());
        $this->authedDelete('/agents/grants/' . $agent['grants'][0]['id'], $session);
        self::assertSame(403, $this->authedGet('/orgs/' . $orgId . '/members', $token)->getStatusCode());
        $this->agentsProblem($this->bearer($token, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []]), 403, 'capability_not_granted');

        $events = $this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::EXECUTED]))->events;
        self::assertSame(['agent', $agent['id'], $userId], [$events[0]->actorType, $events[0]->actorId, $events[0]->subjectId]);
    }

    public function testALocationCapabilityIsReachedOnlyThroughTheRequestMiddleware(): void
    {
        [$userId, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $key = new AgentKey();
        $agent = $this->registerAgent($session, ['name' => 'Inviter', 'auth' => 'private_key_jwt', 'jwk' => $key->jwk()]);
        $id = (string) $agent['id'];
        $asked = $this->json($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => [['name' => 'invite', 'constraints' => ['email' => ['pattern' => '.*@acme\.test'], 'budget' => ['count' => 2]]]], 'preferred_method' => 'in_app']));
        $this->authedPostJson('/agents/approvals/' . $asked['approval']['id'] . '/decide', ['decision' => 'approve'], $session);
        $this->agentsProblem($this->signed($key, $id, 'POST', '/agents/execute', ['capability' => 'invite', 'arguments' => ['email' => 'bob@acme.test']]), 403, 'capability_not_granted', message: 'a location capability does not run here');

        // The host: a tiny PSR-15 handler behind the middleware.
        $handler = new class implements RequestHandlerInterface {
            /** @var list<mixed> */
            public array $seen = [];

            public function first(): mixed
            {
                return $this->seen[0] ?? null;
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->seen[] = $request->getAttribute(AgentRequestMiddleware::GRANT);
                $body = (array) $request->getParsedBody();

                return new JsonResponse(['invited' => $body['email'] ?? null], ($body['email'] ?? '') === 'fail@acme.test' ? 500 : 200);
            }
        };
        $middleware = AgentsPlugin::of($this->graph)->requestMiddleware($this->graph);
        $call = function (?string $jwt, array $body = ['email' => 'bob@acme.test'], string $url = self::LOCATION) use ($middleware, $handler): ResponseInterface {
            $request = $this->serverRequestFor('POST', $url)->withHeader('Content-Type', 'application/json')->withParsedBody($body);
            $request->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR));
            $request->getBody()->rewind();

            return $middleware->process($jwt === null ? $request : $request->withHeader('Authorization', 'Bearer ' . $jwt), $handler);
        };
        $decode = static fn(ResponseInterface $response): array => (array) json_decode((string) $response->getBody(), true);

        self::assertSame(401, $call(null)->getStatusCode(), 'no credential');
        self::assertSame('https://polaris.univeros.io/problems/agents/unauthorized', $decode($call(null))['type']);
        self::assertSame('aud_mismatch', $decode($call($key->requestJwt($id, self::BASE . '/agents/execute')))['error'], 'a JWT for another aud');
        self::assertSame('aud_mismatch', $decode($call($key->requestJwt($id, self::LOCATION, ['capabilities' => ['invite', 'members.list']])))['error'], 'several capabilities at a location');
        self::assertSame('constraint_violated', $decode($call($key->requestJwt($id, self::LOCATION), ['email' => 'bob@evil.test']))['error']);
        self::assertSame('invalid_jwt', $decode($call((new AgentKey())->requestJwt($id, self::LOCATION)))['error'], 'another key');
        self::assertSame([], $handler->seen, 'the handler never ran');

        $ok = $call($key->requestJwt($id, self::LOCATION));
        self::assertSame([200, ['invited' => 'bob@acme.test']], [$ok->getStatusCode(), $decode($ok)]);
        $grant = $handler->first();
        self::assertInstanceOf(Grant::class, $grant);
        self::assertSame(['invite', 1], [$grant->capability, $grant->budgetRemaining]);
        $receipt = $this->graph->get(Receipts::class)->find($ok->getHeaderLine('X-Polaris-Receipt'));
        self::assertSame(['invite', Receipt::OUTCOME_SUCCESS, 2, 1], [$receipt?->capability, $receipt?->outcome, $receipt?->budgetBefore, $receipt?->budgetAfter]);

        $failed = $call($key->requestJwt($id, self::LOCATION), ['email' => 'fail@acme.test']);
        self::assertSame(500, $failed->getStatusCode());
        self::assertSame(Receipt::OUTCOME_FAILED, $this->graph->get(Receipts::class)->find($failed->getHeaderLine('X-Polaris-Receipt'))?->outcome, 'the outcome follows the status');
        self::assertSame('capability_not_granted', $decode($call($key->requestJwt($id, self::LOCATION)))['error'], 'the budget of two is spent: the grant is exhausted');
        self::assertSame(200, $call(null, [], 'https://host.polaris.test/other')->getStatusCode(), 'other URLs pass through');
        self::assertSame([2, 3], [count($this->adapter->findMany(Schema::RECEIPTS, ['agent_id' => $id])), count($handler->seen)], 'two receipts; the pass-through reached the handler too');
        $recorded = $this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::EXECUTED, AuditNames::EXECUTION_DENIED]))->events;
        self::assertSame(['invite', 'invite', 'invite', 'invite', 'invite'], array_column(array_map(static fn($event): array => $event->data, $recorded), 'capability'));
    }
}

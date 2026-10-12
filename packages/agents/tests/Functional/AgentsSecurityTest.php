<?php

declare(strict_types=1);

namespace Polaris\Agents\Tests\Functional;

use Laminas\Diactoros\Response\JsonResponse;
use Override;
use Polaris\Admin\Grants as AdminGrants;
use Polaris\Admin\Principal\Role;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\AuditNames;
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
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The WP4 security review's attacks, each refused: another user's session exchanged for a token naming
 * an agent's public client (a confused deputy), an agent's OAuth client rewritten through the
 * organization's client routes, a capability location reached by another spelling of its URL (or the
 * scheme a proxy hands the application), and an asker choosing its own auto-approval budget.
 */
final class AgentsSecurityTest extends AgentsTestCase
{
    public function testAnotherUsersTokenNamingAnAgentIsRefusedEverywhere(): void
    {
        [$adaId, $ada] = $this->login('ada@example.com');
        [$orgId, $ada] = $this->organization($ada, 'Acme');
        $agent = $this->registerAgent($ada, ['name' => 'Helper', 'auth' => 'delegated_token', 'capabilities' => ['members.list']]);
        $id = (string) $agent['id'];
        [$bobId, $bob] = $this->login('bob@example.com');
        $exchange = fn(string $subject): ResponseInterface => $this->form('/oauth2/token', ['client_id' => $id, 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $subject, 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN, 'scope' => 'members.read']);

        // The exchange is open to any session (the agent's client is public); the token it mints for Bob is dead on arrival.
        $minted = $exchange($bob);
        self::assertSame(200, $minted->getStatusCode(), (string) $minted->getBody());
        $token = (string) $this->json($minted)['access_token'];
        self::assertSame([$bobId, $id], [self::claims($token)['sub'], self::claims($token)['client_id']]);
        $this->agentsProblem($this->bearer($token, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []]), 401, 'invalid_jwt', message: 'execute');
        $this->agentsProblem($this->bearer($token, 'GET', '/agents/session'), 401, 'invalid_jwt', message: 'the session');
        $this->agentsProblem($this->authedGet('/auth/me', $token), 401, 'invalid_jwt', message: 'a core route');
        $this->agentsProblem($this->authedGet('/orgs/' . $orgId . '/members', $token), 401, 'invalid_jwt', message: 'a permissioned core route');
        self::assertSame([], $this->adapter->findMany(Schema::RECEIPTS, ['agent_id' => $id]), 'nothing was chained for Ada');
        self::assertSame([], $this->graph->get(Store::class)->read(new AuditQuery(names: [AuditNames::EXECUTED]))->events, 'no execution was audited as the agent for Ada');

        // Ada's own session exchanged drives the agent as before.
        $own = (string) $this->json($exchange($ada))['access_token'];
        self::assertSame($id, $this->json($this->bearer($own, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []]))['data']['agent']);
        self::assertSame($adaId, $this->json($this->authedGet('/auth/me', $own))['data']['id']);
    }

    public function testAnAgentsClientIsNotManageableThroughTheOrganizationRoutes(): void
    {
        [$userId, $ada] = $this->login('ada@example.com');
        [$orgId, $ada] = $this->organization($ada, 'Acme');
        $agent = $this->registerAgent($ada, ['name' => 'Helper', 'auth' => 'delegated_token', 'capabilities' => ['members.list']]);
        $id = (string) $agent['id'];
        $orgAgent = $this->registerAgent($ada, ['name' => 'Org helper', 'auth' => 'delegated_token', 'organization_id' => $orgId]);
        $client = $this->graph->get(Clients::class)->find($id);
        self::assertNotNull($client);
        self::assertNull($client->organizationId, 'the plugin\'s client belongs to no organization');
        self::assertNull($this->graph->get(Clients::class)->find((string) $orgAgent['id'])?->organizationId, 'an organization\'s agent too');
        self::assertSame($orgId, $orgAgent['organization_id'], 'the agent row carries the organization');

        // The organization's self-service routes do not list, rewrite or delete it.
        self::assertSame([], $this->json($this->authedGet('/orgs/' . $orgId . '/oauth/clients', $ada))['data']);
        $attacker = new AgentKey();
        $rewrite = ['type' => 'confidential', 'token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [[...$attacker->jwk(), 'kid' => $attacker->kid(), 'alg' => 'ES256']]], 'grant_types' => ['client_credentials']];
        foreach (['PATCH' => $this->authedPatch('/orgs/' . $orgId . '/oauth/clients/' . $client->id, $rewrite, $ada), 'DELETE' => $this->authedDelete('/orgs/' . $orgId . '/oauth/clients/' . $client->id, $ada)] as $method => $response) {
            self::assertSame(404, $response->getStatusCode(), $method);
            self::assertSame('https://polaris.univeros.io/problems/oauth/not_found', $this->json($response)['type'], $method);
        }
        self::assertSame(['public', 'none', [Clients::GRANT_EXCHANGE]], [$client->type, $client->tokenEndpointAuthMethod, $client->grantTypes], 'unchanged');
        $this->problem($this->form('/oauth2/token', ['client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion' => $attacker->assertion($id, self::BASE . '/oauth2/token'), 'grant_type' => 'client_credentials', 'scope' => 'members.read']), 401, 'invalid_client', 'the attacker\'s key mints nothing');

        // Operators still see it; the agent still works and the kill switch still disables it.
        $this->graph->get(AdminGrants::class)->grant($userId, Role::Owner);
        self::assertContains($id, array_column($this->json($this->authedGet('/admin/oauth/clients', $ada))['data'], 'client_id'));
        $token = (string) $this->json($this->form('/oauth2/token', ['client_id' => $id, 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $ada, 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN, 'scope' => 'members.read']))['access_token'];
        self::assertSame(200, $this->bearer($token, 'POST', '/agents/execute', ['capability' => 'members.list', 'arguments' => []])->getStatusCode());
        self::assertSame('revoked', $this->json($this->authedPostJson('/agents/' . $id . '/revoke', [], $ada))['data']['status']);
        self::assertNotNull($this->graph->get(Clients::class)->find($id)?->disabledAt);
    }

    public function testEverySpellingOfALocationIsGuardedAndABoundMiddlewareGuardsItsRoute(): void
    {
        [, $ada] = $this->login('ada@example.com');
        [, $ada] = $this->organization($ada, 'Acme');
        $key = new AgentKey();
        $agent = $this->registerAgent($ada, ['name' => 'Inviter', 'auth' => 'private_key_jwt', 'jwk' => $key->jwk()]);
        $id = (string) $agent['id'];
        $asked = $this->json($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => [['name' => 'invite', 'constraints' => ['budget' => ['count' => 10]]]], 'preferred_method' => 'in_app']));
        $this->authedPostJson('/agents/approvals/' . $asked['approval']['id'] . '/decide', ['decision' => 'approve'], $ada);
        $handler = new class implements RequestHandlerInterface {
            public int $calls = 0;

            #[Override]
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                ++$this->calls;

                return new JsonResponse(['invited' => true]);
            }
        };
        $call = function (object $middleware, string $url, ?string $jwt) use ($handler): ResponseInterface {
            $body = ['email' => 'bob@acme.test'];
            $request = $this->serverRequestFor('POST', $url)->withHeader('Content-Type', 'application/json')->withParsedBody($body);
            $request->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR));
            $request->getBody()->rewind();

            return $middleware->process($jwt === null ? $request : $request->withHeader('Authorization', 'Bearer ' . $jwt), $handler);
        };
        $error = static fn(ResponseInterface $response): mixed => ((array) json_decode((string) $response->getBody(), true))['error'] ?? null;

        // Unbound: every spelling of the location, and the scheme a TLS-terminating proxy hands over, is guarded.
        $global = AgentsPlugin::of($this->graph)->requestMiddleware($this->graph);
        foreach ([self::LOCATION, self::LOCATION . '/', 'https://host.polaris.test//invite', 'https://host.polaris.test/./invite', 'https://host.polaris.test/x/../invite', 'https://host.polaris.test:443/invite', 'HTTPS://host.polaris.test/invite', 'https://HOST.polaris.test/invite', 'https://host.polaris.test/%69nvite', 'http://host.polaris.test/invite'] as $url) {
            $response = $call($global, $url, null);
            self::assertSame([401, 'agents_unauthorized'], [$response->getStatusCode(), $error($response)], $url);
        }
        self::assertSame(0, $handler->calls, 'no spelling reached the handler');
        self::assertSame(200, $call($global, self::LOCATION . '/', $key->requestJwt($id, self::LOCATION))->getStatusCode(), 'the aud is compared normalised too');
        self::assertSame('aud_mismatch', $error($call($global, 'http://host.polaris.test/invite', $key->requestJwt($id, self::LOCATION))), 'a proxy\'s http is refused, never passed through');
        self::assertSame(200, $call($global, 'https://host.polaris.test/other', null)->getStatusCode(), 'another URL passes through');
        self::assertSame(2, $handler->calls);

        // Bound to the capability: attached to the route, every request through it is the capability's, whatever the URL.
        $bound = AgentsPlugin::of($this->graph)->requestMiddleware($this->graph, 'invite');
        $route = 'https://api.polaris.test/v2/invitations';
        self::assertSame([401, 'agents_unauthorized'], [$call($bound, $route, null)->getStatusCode(), $error($call($bound, $route, null))]);
        self::assertSame('aud_mismatch', $error($call($bound, $route, $key->requestJwt($id, self::LOCATION))), 'the aud is the URL called');
        $ok = $call($bound, $route, $key->requestJwt($id, $route));
        self::assertSame(200, $ok->getStatusCode());
        self::assertSame('invite', $this->adapter->findOne(Schema::RECEIPTS, ['id' => $ok->getHeaderLine('X-Polaris-Receipt')])['capability'] ?? null);
        self::assertSame(3, $handler->calls);
    }

    public function testTheAskerCannotChooseItsAutoApprovalBudget(): void
    {
        [, $ada] = $this->login('ada@example.com');
        [, $ada] = $this->organization($ada, 'Acme');
        $key = new AgentKey();
        $agent = $this->registerAgent($ada, ['name' => 'Greedy', 'auth' => 'private_key_jwt', 'jwk' => $key->jwk(), 'capabilities' => [['name' => 'members.list', 'constraints' => ['budget' => ['count' => 1000000000]]]]]);
        $id = (string) $agent['id'];
        self::assertSame(['pending', 1000000000, 'in_app'], [$agent['grants'][0]['status'], $agent['grants'][0]['budget']['total'], $agent['approval']['method']], 'wider than the policy\'s 100: a person decides');
        self::assertSame('denied', $this->json($this->authedPostJson('/agents/approvals/' . $agent['approval']['id'] . '/decide', ['decision' => 'deny'], $ada))['data']['grants'][0]['status']);
        $ask = fn(array $budget): array => $this->json($this->signed($key, $id, 'POST', '/agents/grants/request', ['capabilities' => [['name' => 'members.list', 'constraints' => ['budget' => $budget]]], 'preferred_method' => 'in_app']));
        $narrower = $ask(['count' => 10])['agent_capability_grants'][0];
        self::assertSame(['active', 10, 'auto'], [$narrower['status'], $narrower['budget']['total'], $narrower['approved_via']], 'within the ceiling: approved by policy');
        $this->authedDelete('/agents/grants/' . $narrower['id'], $ada);
        $wider = $ask(['count' => 1000]);
        self::assertSame(['pending', 1000], [$wider['agent_capability_grants'][0]['status'], $wider['agent_capability_grants'][0]['budget']['total']]);
        self::assertSame('in_app', $wider['approval']['method']);
        $another = $ask(['amount' => 1, 'field' => 'x']);
        self::assertSame([$wider['agent_capability_grants'][0]['id'], $wider['approval']['id']], [$another['agent_capability_grants'][0]['id'], $another['approval']['id']], 'asking again reuses the pending grant and its approval');
    }
}

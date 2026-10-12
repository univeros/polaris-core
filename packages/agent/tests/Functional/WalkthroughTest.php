<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests\Functional;

use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use Override;
use Polaris\Agent\AgentException;
use Polaris\Agent\AgentKey;
use Polaris\Agent\PolarisAgent;
use Polaris\Agent\Tests\Support\PipelineClient;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\Capability;
use Polaris\Agents\Schema;
use Polaris\OAuth\Tests\Functional\OAuthTestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function array_column;
use function dirname;

/**
 * WP4 acceptance 6 for polaris/agent: the enrol-to-receipt walkthrough through the PSR-15 pipeline,
 * with the plugins of the Slim demo's shape (audit, admin, oauth, agents with one low-risk capability
 * that echoes its arguments): the owner creates a host, the SDK enrols an agent with its own key,
 * requests the grant (approved by policy), executes twice, mints a delegated token by exchange and
 * verifies the receipts and their chain locally, as the server does; a tampered receipt fails both.
 */
final class WalkthroughTest extends OAuthTestCase
{
    #[Override]
    protected static function plugins(): array
    {
        return [...parent::plugins(), new AgentsPlugin(
            baseUrl: self::BASE,
            capabilities: [new Capability(
                'demo.echo',
                'Echo the arguments back',
                ['type' => 'object', 'properties' => ['message' => ['type' => 'string']], 'additionalProperties' => false],
                'members.read',
                'low',
                handler: static fn(array $arguments): array => ['echo' => $arguments],
            )],
            approvalUrl: 'https://app.polaris.test/approve',
            providerName: 'Polaris demo',
        )];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    public function testAnAgentEnrolsGetsItsGrantExecutesAndVerifiesItsReceiptChain(): void
    {
        [, $session] = $this->login('ada@example.com');
        [, $session] = $this->organization($session, 'Acme');
        $host = $this->json($this->authedPostJson('/agents/hosts', ['name' => 'Laptop'], $session))['data'];
        $client = new PipelineClient(fn(ServerRequestInterface $request): ResponseInterface => $this->handle($request));
        $key = AgentKey::generate('EdDSA');

        // Discovery, enrolment with the host's token, the grant by policy.
        $sdk = PolarisAgent::create(self::BASE, $client, new RequestFactory(), new StreamFactory(), $key);
        self::assertSame(['Polaris demo', self::BASE, self::BASE . '/oauth2/token'], [$sdk->configuration->providerName(), $sdk->configuration->mount, $sdk->configuration->tokenEndpoint]);
        $enrolled = $sdk->enroll($host['enrollment_token'], ['name' => 'Claude Code', 'mode' => 'delegated']);
        self::assertSame([$host['id'], 'EdDSA', $key->kid], [$enrolled['host_id'], $enrolled['public_jwk']['alg'], $enrolled['public_jwk']['kid']]);
        $agent = $sdk->bound($enrolled['id']);
        $asked = $agent->requestGrants(['demo.echo'], ['reason' => 'The walkthrough']);
        self::assertSame([[['demo.echo', 'active', 'auto']], null], [array_map(static fn(array $grant): array => [$grant['capability'], $grant['status'], $grant['approved_via']], $asked['agent_capability_grants']), $asked['approval'] ?? null]);
        self::assertSame('active', array_column($agent->capabilities(), 'grant_status', 'name')['demo.echo']);

        // Two executions with signed request JWTs; the session shows the budget spent.
        $first = $agent->execute('demo.echo', ['message' => 'hello']);
        self::assertSame([['echo' => ['message' => 'hello']], 1], [$first['data'], $first['receipt']['seq']]);
        self::assertSame(2, $agent->execute('demo.echo', ['message' => 'again'])['receipt']['seq']);
        $me = $agent->session();
        self::assertSame(['jwt', 'Laptop', 98], [$me['authenticated_via'], $me['host']['name'], $me['grants'][0]['budget']['remaining']]);
        try {
            $agent->execute('demo.echo', ['nope' => 1]);
            self::fail('the schema');
        } catch (AgentException $exception) {
            self::assertSame([422, 'agents_invalid_arguments'], [$exception->status, $exception->error]);
        }

        // A delegated token by exchange, with a private_key_jwt assertion; it serves the agent's routes.
        $token = $agent->token(['subject_token' => $session, 'scope' => 'members.read']);
        self::assertSame('oauth', $agent->withToken($token['access_token'])->session()['authenticated_via']);

        // The chain as the owner lists it, verified locally against the JWKS and remotely; a tampered one fails.
        $chain = $this->json($this->authedGet('/agents/' . $enrolled['id'] . '/receipts', $session))['data'];
        self::assertSame([1, 2], array_column($chain, 'seq'));
        self::assertSame(['valid' => true, 'checks' => ['hash' => true, 'signature' => true, 'chain' => true]], $agent->verifyReceipt($chain[0]));
        self::assertSame(['valid' => true, 'checks' => ['hash' => true, 'signature' => true, 'chain' => true]], $agent->verifyReceipt($chain[1], $chain[0]));
        self::assertTrue($this->json($this->authedGet('/agents/receipts/' . $chain[1]['id'] . '/verify', $session))['data']['valid']);
        $this->adapter->update(Schema::RECEIPTS, ['id' => $chain[0]['id']], ['budget_after' => 42]);
        $tampered = $this->json($this->authedGet('/agents/' . $enrolled['id'] . '/receipts', $session))['data'];
        self::assertSame(['hash' => false, 'signature' => false, 'chain' => true], $agent->verifyReceipt($tampered[0])['checks']);
        self::assertSame(['hash' => true, 'signature' => true, 'chain' => false], $agent->verifyReceipt($tampered[1], $tampered[0])['checks']);
    }
}

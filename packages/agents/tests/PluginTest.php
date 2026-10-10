<?php

declare(strict_types=1);

namespace Polaris\Agents\Tests;

use DateTimeImmutable;
use LogicException;
use Opis\JsonSchema\Validator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\AdminPlugin;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Agents\AgentAuthenticator;
use Polaris\Agents\AgentException;
use Polaris\Agents\AgentKeys;
use Polaris\Agents\Agents;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\Approvals;
use Polaris\Agents\AuditNames;
use Polaris\Agents\AuthenticatedAgent;
use Polaris\Agents\Capabilities;
use Polaris\Agents\Capability;
use Polaris\Agents\Constraints;
use Polaris\Agents\Discovery;
use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Executor;
use Polaris\Agents\GrantRequests;
use Polaris\Agents\Grants;
use Polaris\Agents\Hosts;
use Polaris\Agents\Http\AgentPrincipalMiddleware;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Grant;
use Polaris\Agents\Model\Receipt;
use Polaris\Agents\Receipts;
use Polaris\Agents\RequestJwt;
use Polaris\Agents\Schema;
use Polaris\Agents\Settings;
use Polaris\Agents\Tests\Support\AgentKey;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\OAuth\OAuthPlugin;
use Polaris\Polaris;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\RecordingEventDispatcher;
use Polaris\Tests\Support\TestKeys;
use Polaris\Token\Token;
use Polaris\Wiring\Config;
use Polaris\Wiring\Graph;
use Symfony\Component\Uid\Uuid;

use function dirname;
use function file_get_contents;
use function hash;
use function json_decode;
use function json_encode;
use function preg_match;
use function str_repeat;
use function str_starts_with;

/**
 * The plugin wired through `Polaris::create()`, and the services on their own: the settings and
 * capability validation, constraints and budgets, the receipt chain's canonical JSON and hash, the
 * request JWT rules, and the discovery document against the protocol document's JSON Schema
 * (acceptance 6). Separate processes: the schema registry is static.
 */
#[CoversClass(AgentsPlugin::class)]
#[CoversClass(Settings::class)]
#[CoversClass(Capability::class)]
#[CoversClass(Capabilities::class)]
#[CoversClass(Constraints::class)]
#[CoversClass(Grants::class)]
#[CoversClass(Receipts::class)]
#[CoversClass(RequestJwt::class)]
#[CoversClass(Discovery::class)]
#[CoversClass(AgentKeys::class)]
#[CoversClass(Schema::class)]
#[RunTestsInSeparateProcesses]
final class PluginTest extends TestCase
{
    private const string NOW = '2026-10-10T10:00:00+00:00';
    private const string BASE = 'https://auth.polaris.test';
    private const string EXECUTE = self::BASE . '/agents/execute';

    private MutableClock $clock;
    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->clock = new MutableClock(new DateTimeImmutable(self::NOW));
        $this->events = new RecordingEventDispatcher();
    }

    public function testEverythingIsWiredThroughTheGraph(): void
    {
        $polaris = $this->polaris();
        $graph = $polaris->graph();
        $tables = [];
        foreach ($polaris->schema() as $model) {
            $tables[] = $model->table;
        }
        foreach ([Schema::AGENTS, Schema::HOSTS, Schema::GRANTS, Schema::APPROVALS, Schema::RECEIPTS] as $table) {
            self::assertContains($table, $tables);
        }
        $routes = 0;
        foreach ($graph->manifest()->endpoints() as $spec) {
            if ($spec->plugin === AgentsPlugin::ID) {
                ++$routes;
                $graph->endpoint($spec->class);
            }
        }
        self::assertSame(23, $routes);
        self::assertInstanceOf(AgentPrincipalMiddleware::class, AgentsPlugin::of($graph)->middleware($graph)[0]);
        $polaris->listeners();
        self::assertTrue($graph->get(Catalog::class)->has(AuditNames::EXECUTED));
        self::assertSame(['deploy.staging' => 'Required by the agent capability "deploy"', 'billing.refund' => 'Required by the agent capability "refund"'], AgentsPlugin::of($graph)->permissions(), 'core permissions are not re-contributed');
        self::assertArrayHasKey('deploy.staging', $graph->permissionCatalog()->permissions());
        self::assertSame([], AgentsPlugin::of($graph)->mcpTools($graph, null));
        AgentsPlugin::of($graph)->requestMiddleware($graph);
    }

    public function testTheSettingsAndCapabilitiesAreValidated(): void
    {
        self::assertSame(Settings::DEFAULT_STRENGTHS, (new Settings(self::BASE))->strengths);
        self::assertSame('passkey', (new Settings(self::BASE, strengths: ['high' => 'passkey']))->strengthFor('high'));
        foreach (
            [
            static fn(): Settings => new Settings('not a url'),
            static fn(): Settings => new Settings(self::BASE, approvalUrl: 'https://app.test/approve?x=1'),
            static fn(): Settings => new Settings(self::BASE, autoApprove: ['critical' => true]),
            static fn(): Settings => new Settings(self::BASE, autoApprove: ['low' => ['count' => 0]]),
            static fn(): Settings => new Settings(self::BASE, strengths: ['high' => 'biometric']),
            static fn(): Settings => new Settings(self::BASE, requestJwtMaxAge: 600),
            static fn(): Capability => new Capability('Deploy', 'x', [], 'deploy', handler: static fn(): null => null),
            static fn(): Capability => new Capability('deploy', 'x', [], 'deploy', 'critical', handler: static fn(): null => null),
            static fn(): Capability => new Capability('deploy', 'x', [], 'deploy'),
            static fn(): Capability => new Capability('deploy', 'x', [], 'deploy', location: 'https://h.test/x', handler: static fn(): null => null),
            static fn(): Capabilities => new Capabilities([self::capability('a', 'low'), self::capability('a', 'low')]),
            ] as $invalid
        ) {
            try {
                $invalid();
                self::fail('Expected a LogicException');
            } catch (LogicException $exception) {
                self::assertNotSame('', $exception->getMessage());
            }
        }
    }

    public function testConstraintsAreParsedAndEvaluated(): void
    {
        $parsed = Constraints::parse(['amount' => ['max' => 100, 'min' => 1], 'currency' => ['in' => ['EUR', 'USD']], 'env' => ['not_in' => ['prod']], 'ref' => ['pattern' => '[a-z]+-\d+'], 'budget' => ['amount' => 500, 'field' => 'amount', 'window' => 3600]]);
        self::assertSame(['kind' => 'amount', 'total' => 500, 'field' => 'amount', 'window' => 3600], $parsed['budget']);
        self::assertSame([], Constraints::violations($parsed['fields'], ['amount' => 50, 'currency' => 'EUR', 'env' => 'staging', 'ref' => 'abc-12']));
        self::assertSame([
            ['field' => 'amount', 'constraint' => 'max', 'actual' => 150],
            ['field' => 'currency', 'constraint' => 'in', 'actual' => 'GBP'],
            ['field' => 'env', 'constraint' => 'not_in', 'actual' => 'prod'],
            ['field' => 'ref', 'constraint' => 'pattern', 'actual' => null],
        ], Constraints::violations($parsed['fields'], ['amount' => 150, 'currency' => 'GBP', 'env' => 'prod']));
        try {
            Constraints::parse(['amount' => ['between' => [1, 2]]]);
            self::fail();
        } catch (AgentException $exception) {
            self::assertSame([AgentException::UNKNOWN_CONSTRAINT_OPERATOR, 400], [$exception->type, $exception->status]);
        }
        try {
            Constraints::budget(['count' => 1, 'amount' => 2]);
            self::fail();
        } catch (AgentException $exception) {
            self::assertSame(AgentException::INVALID_INPUT, $exception->type);
        }
        $grant = new Grant();
        $grant->budgetKind = Grant::BUDGET_AMOUNT;
        $grant->budgetField = 'amount';
        self::assertSame(13, Constraints::cost($grant, ['amount' => 12.5]));
        self::assertSame(1, Constraints::cost(new Grant(), ['amount' => 12.5]));
    }

    public function testBudgetsAreSpentByAConditionalUpdate(): void
    {
        $graph = $this->polaris(autoApprove: [])->graph();
        $agent = $this->agent($graph);
        $grants = $graph->get(Grants::class);
        $pending = $grants->request($agent, [['name' => 'refund', 'constraints' => ['budget' => ['amount' => 10, 'field' => 'amount']]]]);
        self::assertSame(Grant::STATUS_PENDING, $pending['grants'][0]->status);
        $grant = $pending['grants'][0];
        $grants->approve($grant, 'owner', 'in_app');
        self::assertSame(10, $grant->budgetRemaining);
        self::assertSame(7, $grants->spend($grant, 3));
        self::assertNull($grants->spend($grant, 8), 'more than what is left spends nothing');
        self::assertSame(7, $grants->find($grant->id)?->budgetRemaining);
        self::assertSame(0, $grants->spend($grant, 7));
        $grants->exhaust($grant);
        self::assertSame(Grant::STATUS_EXHAUSTED, $grants->find($grant->id)?->status);
        self::assertNull($grants->activeFor($agent, 'refund'));
        try {
            $grants->approve($grant, 'owner', 'in_app');
            self::fail();
        } catch (AgentException $exception) {
            self::assertSame(AgentException::CONFLICT, $exception->type);
        }
    }

    public function testReceiptsChainHashAndVerify(): void
    {
        $graph = $this->polaris()->graph();
        $agent = $this->agent($graph);
        $receipts = $graph->get(Receipts::class);
        self::assertSame('{"a":{"b":[2,1],"c":"x/y"},"z":null}', Receipts::canonical(['z' => null, 'a' => ['c' => 'x/y', 'b' => [2, 1]]]));
        $first = $receipts->append($agent, null, 'deploy', Receipts::inputHash(['build' => '1']), Receipt::OUTCOME_SUCCESS, 10, 9);
        $second = $receipts->append($agent, null, 'deploy', Receipts::inputHash(['build' => '2']), Receipt::OUTCOME_SUCCESS, 9, 8);
        self::assertSame([1, 2, null, $first->hash], [$first->seq, $second->seq, $first->prevHash, $second->prevHash]);
        self::assertSame(hash('sha256', Receipts::canonical($second->hashed())), $second->hash);
        self::assertSame(['valid' => true, 'checks' => ['hash' => true, 'signature' => true, 'chain' => true]], $receipts->verify($second));
        $second->outcome = Receipt::OUTCOME_FAILED;
        self::assertSame(['hash' => false, 'signature' => false, 'chain' => true], $receipts->verify($second)['checks'], 'a changed field breaks the hash and the signature');
        $sealed = $receipts->seal($agent);
        self::assertSame(Receipt::OUTCOME_SEALED, $sealed->outcome);
        try {
            $receipts->append($agent, null, 'deploy', Receipts::inputHash([]), Receipt::OUTCOME_SUCCESS, null, null);
            self::fail();
        } catch (AgentException $exception) {
            self::assertSame(AgentException::SEALED, $exception->type);
        }
    }

    public function testRequestJwtsAreVerifiedAgainstTheAgentsKeyAndTheRequest(): void
    {
        $graph = $this->polaris()->graph();
        $jwts = $graph->get(RequestJwt::class);
        $now = $this->clock->now()->getTimestamp();
        foreach (['ES256', 'EdDSA'] as $alg) {
            $key = new AgentKey($alg);
            $agent = $this->agent($graph, $key);
            $body = '{"capability":"deploy"}';
            $verified = $jwts->verify($key->requestJwt($agent->id, self::EXECUTE, ['htm' => 'POST', 'htu' => self::EXECUTE . '?x=1', 'body_hash' => AgentKey::bodyHash($body), 'capabilities' => ['deploy']], now: $now), $agent, 'POST', self::EXECUTE . '?x=1', $body);
            self::assertSame(['deploy'], $verified['capabilities']);
            $refused = [
                'aud' => $key->requestJwt($agent->id, self::BASE . '/agents/session', now: $now),
                'aud with query' => $key->requestJwt($agent->id, self::EXECUTE . '?x=1', now: $now),
                'exp - iat > 300' => $key->requestJwt($agent->id, self::EXECUTE, ['exp' => $now + 301], now: $now),
                'expired' => $key->requestJwt($agent->id, self::EXECUTE, ['iat' => $now - 400, 'exp' => $now - 100], now: $now),
                'no jti' => $key->requestJwt($agent->id, self::EXECUTE, ['jti' => null], now: $now),
                'another agent' => $key->requestJwt(Uuid::v7()->toRfc4122(), self::EXECUTE, now: $now),
                'wrong key' => (new AgentKey($alg))->requestJwt($agent->id, self::EXECUTE, now: $now),
                'jku header' => $key->requestJwt($agent->id, self::EXECUTE, [], ['jku' => 'https://evil.test/jwks'], now: $now),
                'jwk header' => $key->requestJwt($agent->id, self::EXECUTE, [], ['jwk' => $key->jwk()], now: $now),
                'typ' => $key->requestJwt($agent->id, self::EXECUTE, [], ['typ' => 'JWT'], now: $now),
                'htm' => $key->requestJwt($agent->id, self::EXECUTE, ['htm' => 'GET'], now: $now),
                'htu' => $key->requestJwt($agent->id, self::EXECUTE, ['htu' => self::BASE . '/other'], now: $now),
                'body_hash' => $key->requestJwt($agent->id, self::EXECUTE, ['body_hash' => AgentKey::bodyHash('{}')], now: $now),
                'capabilities shape' => $key->requestJwt($agent->id, self::EXECUTE, ['capabilities' => 'deploy'], now: $now),
            ];
            foreach ($refused as $why => $jwt) {
                try {
                    $jwts->verify($jwt, $agent, 'POST', self::EXECUTE, $body);
                    self::fail($why . ' should be refused');
                } catch (AgentException $exception) {
                    self::assertSame(str_starts_with($why, 'aud') ? AgentException::AUD_MISMATCH : AgentException::INVALID_JWT, $exception->type, $why);
                }
            }
            $replayed = $key->requestJwt($agent->id, self::EXECUTE, now: $now);
            $jwts->verify($replayed, $agent, 'POST', self::EXECUTE, $body);
            try {
                $jwts->verify($replayed, $agent, 'POST', self::EXECUTE, $body);
                self::fail('a jti is used once');
            } catch (AgentException $exception) {
                self::assertStringContainsString('jti', $exception->detail);
            }
        }
        $withoutKey = $this->agent($graph, null);
        try {
            $jwts->verify((new AgentKey())->requestJwt($withoutKey->id, self::EXECUTE, now: $now), $withoutKey, 'POST', self::EXECUTE, '');
            self::fail();
        } catch (AgentException $exception) {
            self::assertStringContainsString('no registered key', $exception->detail);
        }
    }

    public function testAgentRegistrationIsValidated(): void
    {
        $graph = $this->polaris()->graph();
        $agents = $graph->get(Agents::class);
        $key = new AgentKey();
        foreach (
            [
            ['name' => '', 'mode' => 'delegated', 'auth' => 'client_secret'],
            ['name' => 'X', 'mode' => 'hybrid', 'auth' => 'client_secret'],
            ['name' => 'X', 'mode' => 'delegated', 'auth' => 'password'],
            ['name' => 'X', 'mode' => 'autonomous', 'auth' => 'delegated_token'],
            ['name' => 'X', 'mode' => 'delegated', 'auth' => 'private_key_jwt'],
            ['name' => 'X', 'mode' => 'delegated', 'auth' => 'private_key_jwt', 'jwk' => [...$key->jwk(), 'd' => 'secret']],
            ] as $fields
        ) {
            try {
                $agents->create($fields, Agent::OWNER_USER, 'user-1', null, 'user-1', null);
                self::fail((string) json_encode($fields));
            } catch (AgentException $exception) {
                self::assertSame(AgentException::INVALID_INPUT, $exception->type);
            }
        }
        [$public] = $agents->create(['name' => 'X', 'mode' => 'delegated', 'auth' => 'delegated_token'], Agent::OWNER_USER, 'user-1', null, 'user-1', null);
        self::assertSame(['public', 'none', ['urn:ietf:params:oauth:grant-type:token-exchange'], ['profile']], [$agents->client($public)?->type, $agents->client($public)?->tokenEndpointAuthMethod, $agents->client($public)?->grantTypes, $agents->client($public)?->scopes]);
    }

    public function testTheAgentKeyIsValidatedAndGetsAKid(): void
    {
        $key = new AgentKey();
        $jwk = AgentKeys::publicJwk($key->jwk());
        self::assertSame(['ES256', $key->kid(), 'sig'], [$jwk['alg'], $jwk['kid'], $jwk['use']]);
        self::assertSame('EdDSA', AgentKeys::publicJwk((new AgentKey('EdDSA'))->jwk())['alg']);
        foreach ([null, ['kty' => 'RSA', 'n' => 'x', 'e' => 'AQAB'], [...$key->jwk(), 'd' => 'secret'], ['kty' => 'EC', 'crv' => 'P-384', 'x' => 'a', 'y' => 'b'], [...$key->jwk(), 'alg' => 'EdDSA']] as $invalid) {
            try {
                AgentKeys::publicJwk($invalid);
                self::fail();
            } catch (AgentException $exception) {
                self::assertSame(AgentException::INVALID_INPUT, $exception->type);
            }
        }
    }

    public function testTheDiscoveryDocumentValidatesAgainstTheProtocolSchema(): void
    {
        $markdown = (string) file_get_contents(dirname(__DIR__, 3) . '/docs/better/agent-auth-compat.md');
        self::assertSame(1, preg_match('/```json\n(.*?)\n```/s', $markdown, $matches), 'the protocol document holds the schema');
        $schema = json_decode($matches[1]);
        $document = $this->polaris()->graph()->get(Discovery::class)->document();
        $result = (new Validator())->validate(json_decode((string) json_encode($document)), $schema);
        self::assertTrue($result->isValid(), (string) json_encode($result->error()?->message()));
        self::assertSame($document['endpoints']['execute'], $document['default_location']);
        self::assertSame(self::BASE . '/oauth2/token', $document['token_endpoint']);
        self::assertArrayNotHasKey('mcp', $document['endpoints'], 'no mcp plugin registered');
    }

    public function testEventsAreAuditableWithTheAgentAsActor(): void
    {
        $event = AgentEvent::byAgent(AuditNames::EXECUTED, 'agent-1', 'user-1', 'org-1', ['capability' => 'deploy']);
        $audit = $event->toAuditEvent($this->clock);
        self::assertSame(['agent', 'agent-1', 'user-1', 'org-1', ['agent_id' => 'agent-1', 'capability' => 'deploy']], [$audit->actorType, $audit->actorId, $audit->subjectId, $audit->organizationId, $audit->data]);
        self::assertSame('user', AgentEvent::byUser(AuditNames::REVOKED, 'agent-1', 'user-1', null)->toAuditEvent($this->clock)->actorType);
    }

    public function testHostsAuthenticateByTheirEnrolmentToken(): void
    {
        $graph = $this->polaris()->graph();
        $hosts = $graph->get(Hosts::class);
        [$host, $token] = $hosts->create(Agent::OWNER_USER, 'user-1', null, 'user-1', 'Laptop', ['deploy']);
        self::assertStringStartsWith('peh_', $token);
        self::assertSame($host->id, $hosts->authenticate($token)?->id);
        self::assertNull($hosts->authenticate('peh_' . str_repeat('x', 43)));
        self::assertNull($hosts->authenticate('pk_live_' . str_repeat('x', 43)));
        $hosts->revoke($host);
        self::assertNull($hosts->authenticate($token));
        try {
            $hosts->create(Agent::OWNER_USER, 'user-1', null, 'user-1', 'Laptop', ['nope']);
            self::fail();
        } catch (AgentException $exception) {
            self::assertSame(AgentException::CAPABILITY_NOT_FOUND, $exception->type);
        }
    }

    public function testExecutionIsRefusedWithoutAGrantAndRecorded(): void
    {
        $graph = $this->polaris()->graph();
        $agent = $this->agent($graph);
        $executor = $graph->get(Executor::class);
        $principal = AuthenticatedAgent::viaJwt($agent, null);
        foreach (['nope' => AgentException::CAPABILITY_NOT_FOUND, 'deploy' => AgentException::CAPABILITY_NOT_GRANTED] as $capability => $type) {
            try {
                $executor->execute($principal, $capability, ['build' => '1']);
                self::fail();
            } catch (AgentException $exception) {
                self::assertSame($type, $exception->type);
            }
        }
        self::assertCount(2, $this->events->ofType(AgentEvent::class));
        self::assertNull($graph->get(AgentAuthenticator::class)->fromToken(new Token('x', ['client_id' => 'nobody'])));
        self::assertNotNull($graph->get(GrantRequests::class)->request($agent, ['deploy'], null, null, null, true)['approval'], 'the owner holds no permission: pending with an approval');
        self::assertCount(1, $graph->get(Approvals::class)->pendingFor([$agent]));
    }

    private function polaris(array $autoApprove = Settings::DEFAULT_AUTO_APPROVE): Polaris
    {
        $keys = TestKeys::rsa();

        return Polaris::create(new Config(
            secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
            auth: AuthConfig::fromArray(['issuer' => self::BASE]),
            database: new InMemoryAdapter(),
            clock: $this->clock,
            dispatcher: $this->events,
            plugins: [new AuditPlugin(), new AdminPlugin(), new OAuthPlugin(self::BASE), new AgentsPlugin(self::BASE, [self::capability('deploy', 'low'), self::capability('refund', 'high', 'billing.refund'), ['name' => 'members', 'description' => 'List members', 'permission' => 'members.read', 'risk' => 'low', 'handler' => static fn(): array => []]], $autoApprove)],
        ));
    }

    private static function capability(string $name, string $risk, ?string $permission = null): Capability
    {
        return new Capability($name, 'The ' . $name . ' capability', ['type' => 'object', 'properties' => ['build' => ['type' => 'string'], 'amount' => ['type' => 'number']]], $permission ?? 'deploy.staging', $risk, handler: static fn(array $arguments): array => ['ran' => $arguments]);
    }

    private function agent(Graph $graph, ?AgentKey $key = new AgentKey()): Agent
    {
        $fields = $key === null ? ['name' => 'Bot', 'mode' => 'autonomous', 'auth' => 'client_secret'] : ['name' => 'Bot', 'mode' => 'delegated', 'auth' => 'private_key_jwt', 'jwk' => $key->jwk()];
        [$agent] = $graph->get(Agents::class)->create($fields, Agent::OWNER_USER, Uuid::v7()->toRfc4122(), null, 'creator', null);

        return $agent;
    }
}

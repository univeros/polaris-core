<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use LogicException;
use PHPUnit\Framework\TestCase;
use Polaris\Agent\AgentException;
use Polaris\Agent\AgentKey;
use Polaris\Agent\PolarisAgent;
use Polaris\Agent\Tests\Support\FakeClient;
use Polaris\Agent\Tests\Support\Fixtures;
use Psr\Http\Message\RequestInterface;

use function array_map;
use function base64_encode;
use function hash;
use function json_decode;
use function parse_str;
use function substr;

final class PolarisAgentTest extends TestCase
{
    private FakeClient $http;

    protected function setUp(): void
    {
        $this->http = new FakeClient();
    }

    private function agent(?AgentKey $key = null, ?string $agentId = null, ?string $accessToken = null, ?string $clientSecret = null): PolarisAgent
    {
        return new PolarisAgent(Fixtures::configuration(), $this->http, new RequestFactory(), new StreamFactory(), $key, $agentId, $accessToken, $clientSecret);
    }

    /**
     * @return array<string, mixed>
     */
    private static function registered(): array
    {
        return ['id' => 'agent-1', 'owner_type' => 'user', 'owner_id' => 'u1', 'name' => 'Bot', 'mode' => 'delegated', 'host_id' => 'h1', 'auth' => 'private_key_jwt', 'status' => 'active', 'grants' => [Fixtures::grant()], 'approval' => null];
    }

    private static function bearer(RequestInterface $request): string
    {
        return substr($request->getHeaderLine('Authorization'), 7);
    }

    /**
     * @return list<string>
     */
    private function calls(): array
    {
        return array_map(static fn(RequestInterface $request): string => $request->getMethod() . ' ' . $request->getUri(), $this->http->requests);
    }

    public function testItDiscoversTheConfigurationUnderTheMountOrAtTheDocumentsUrl(): void
    {
        $this->http->answer(200, Fixtures::configuration()->document);
        $configuration = PolarisAgent::discover(Fixtures::MOUNT . '/', $this->http, new RequestFactory(), new StreamFactory());
        self::assertSame([Fixtures::MOUNT, Fixtures::MOUNT . '/oauth2/token', Fixtures::MOUNT . '/mcp', 'Polaris test'], [$configuration->mount, $configuration->tokenEndpoint, $configuration->mcpEndpoint(), $configuration->providerName()]);
        PolarisAgent::create(Fixtures::MOUNT . '/.well-known/agent-configuration', $this->http, new RequestFactory(), new StreamFactory());
        self::assertSame(['GET ' . Fixtures::MOUNT . '/.well-known/agent-configuration', 'GET ' . Fixtures::MOUNT . '/.well-known/agent-configuration'], $this->calls());
        $this->http->answer(200, ['issuer' => 'x']);
        $this->expectExceptionMessage('Not an agent configuration document');
        PolarisAgent::discover(Fixtures::MOUNT, (new FakeClient())->answer(200, ['issuer' => 'x']), new RequestFactory(), new StreamFactory());
    }

    public function testItEnrolsWithTheHostsTokenAndItsPublicJwkThenSignsEveryCallForItsExactUrlAndBody(): void
    {
        $key = AgentKey::generate();
        $this->http->answer(201, ['data' => self::registered()])->answer(200, ['data' => ['hello' => 'world'], 'receipt' => ['id' => 'r1', 'seq' => 1, 'hash' => 'h']])->answer(200, ['data' => ['grants' => [Fixtures::grant()]]]);
        $sdk = $this->agent($key);
        self::assertNull($sdk->agentId);

        $enrolled = $sdk->enroll('peh_token', ['name' => 'Bot', 'mode' => 'delegated']);
        self::assertSame('demo.echo', $enrolled['grants'][0]['capability']);
        $request = $this->http->last();
        self::assertSame(['POST', Fixtures::MOUNT . '/agents/enroll', 'Bearer peh_token', 'application/json'], [$request->getMethod(), (string) $request->getUri(), $request->getHeaderLine('Authorization'), $request->getHeaderLine('Content-Type')]);
        self::assertSame(['name' => 'Bot', 'mode' => 'delegated', 'auth' => 'private_key_jwt', 'jwk' => $key->publicJwk], json_decode((string) $request->getBody(), true));

        $agent = $sdk->bound($enrolled['id']);
        $executed = $agent->execute('demo.echo', ['hello' => 'world'], ['demo.echo']);
        self::assertSame('world', $executed['data']['hello']);
        $request = $this->http->last();
        $body = (string) $request->getBody();
        self::assertSame('{"capability":"demo.echo","arguments":{"hello":"world"}}', $body);
        ['header' => $header, 'claims' => $claims] = Fixtures::decode(self::bearer($request));
        self::assertSame('agent+jwt', $header['typ']);
        self::assertSame(['agent-1', Fixtures::MOUNT . '/agents/execute', 'POST', AgentKey::base64Url(hash('sha256', $body, true)), ['demo.echo']], [$claims['sub'], $claims['aud'], $claims['htm'], $claims['body_hash'], $claims['capabilities']]);
        self::assertSame('agent-1', JWT::decode(self::bearer($request), JWK::parseKey($key->publicJwk))->sub, 'verifies with the public JWK');

        $agent->session();
        $claims = Fixtures::decode(self::bearer($this->http->last()))['claims'];
        self::assertSame([Fixtures::MOUNT . '/agents/session', 'GET'], [$claims['aud'], $claims['htm']]);
        self::assertArrayNotHasKey('body_hash', $claims);
        $this->http->answer(200, ['data' => [], 'receipt' => []]);
        $agent->execute('demo.echo');
        self::assertSame('{"capability":"demo.echo","arguments":{}}', (string) $this->http->last()->getBody(), 'empty arguments are an object');

        $this->expectException(LogicException::class);
        $sdk->execute('demo.echo');
    }

    public function testItRegistersThroughTheOwnerWithASecretWhenItHasNoKeyAndAsksForGrantsInAapsShape(): void
    {
        $this->http->answer(201, ['data' => [...self::registered(), 'auth' => 'client_secret', 'client_secret' => 'pcs_x']])->answer(200, ['agent_id' => 'agent-1', 'agent_capability_grants' => [], 'approval' => null]);
        $sdk = $this->agent();
        $registered = $sdk->register('owner-token', ['name' => 'Bot', 'mode' => 'autonomous', 'organization_id' => 'o1', 'capabilities' => ['demo.echo']]);
        self::assertSame('pcs_x', $registered['client_secret']);
        self::assertSame(['name' => 'Bot', 'mode' => 'autonomous', 'organization_id' => 'o1', 'capabilities' => ['demo.echo'], 'auth' => 'client_secret'], json_decode((string) $this->http->last()->getBody(), true));

        $sdk->bound('agent-1')->withToken('access')->requestGrants([['name' => 'org.rename', 'constraints' => ['name' => ['pattern' => 'Acme.*']]]], ['preferred_method' => 'device_authorization', 'reason' => 'Rename']);
        $request = $this->http->last();
        self::assertSame(['POST', Fixtures::MOUNT . '/agents/grants/request', 'Bearer access'], [$request->getMethod(), (string) $request->getUri(), $request->getHeaderLine('Authorization')]);
        self::assertSame(['capabilities' => [['name' => 'org.rename', 'constraints' => ['name' => ['pattern' => 'Acme.*']]]], 'preferred_method' => 'device_authorization', 'reason' => 'Rename'], json_decode((string) $request->getBody(), true));
        $this->expectExceptionMessage('no key and no access token');
        $sdk->bound('agent-1')->execute('demo.echo');
    }

    public function testItMintsTokensWithAnAssertionWithTheSecretAndByExchange(): void
    {
        $key = AgentKey::generate('EdDSA');
        $this->http->answer(200, ['access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 3600]);
        self::assertSame('at', $this->agent($key, 'agent-1')->token(['scope' => 'members.read', 'resource' => Fixtures::MOUNT . '/mcp'])['access_token']);
        $request = $this->http->last();
        parse_str((string) $request->getBody(), $form);
        self::assertSame(['POST', Fixtures::MOUNT . '/oauth2/token', 'application/x-www-form-urlencoded'], [$request->getMethod(), (string) $request->getUri(), $request->getHeaderLine('Content-Type')]);
        self::assertSame(['client_credentials', 'members.read', Fixtures::MOUNT . '/mcp', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'], [$form['grant_type'], $form['scope'], $form['resource'], $form['client_assertion_type']]);
        $assertion = Fixtures::decode((string) $form['client_assertion'])['claims'];
        self::assertSame(['agent-1', 'agent-1', Fixtures::MOUNT . '/oauth2/token'], [$assertion['iss'], $assertion['sub'], $assertion['aud']]);
        self::assertSame('agent-1', JWT::decode((string) $form['client_assertion'], JWK::parseKey($key->publicJwk))->sub);

        $this->agent(null, 'agent-1', null, 'pcs_x')->token(['subject_token' => 'user-access']);
        $request = $this->http->last();
        parse_str((string) $request->getBody(), $exchange);
        self::assertSame('Basic ' . base64_encode('agent-1:pcs_x'), $request->getHeaderLine('Authorization'));
        self::assertSame(['urn:ietf:params:oauth:grant-type:token-exchange', 'user-access', 'urn:ietf:params:oauth:token-type:access_token', false], [$exchange['grant_type'], $exchange['subject_token'], $exchange['subject_token_type'], isset($exchange['client_assertion'])]);

        $this->agent(null, 'agent-1')->token(['subject_token' => 'user-access']);
        parse_str((string) $this->http->last()->getBody(), $public);
        self::assertSame('agent-1', $public['client_id']);
    }

    public function testARefusalIsThrownWithItsProblemDocument(): void
    {
        $problem = ['type' => 'https://polaris.univeros.io/problems/agents/constraint_violated', 'title' => 'Forbidden', 'status' => 403, 'detail' => 'amount is above 50', 'error' => 'constraint_violated', 'violations' => [['field' => 'amount', 'constraint' => 'max', 'actual' => 60]]];
        $this->http->answer(403, $problem);
        try {
            $this->agent(null, 'agent-1', 'at')->execute('credits.spend', ['amount' => 60]);
            self::fail('refused');
        } catch (AgentException $exception) {
            self::assertSame([403, 'constraint_violated', $problem], [$exception->status, $exception->error, $exception->problem]);
            self::assertStringContainsString('amount is above 50', $exception->getMessage());
        }
    }
}

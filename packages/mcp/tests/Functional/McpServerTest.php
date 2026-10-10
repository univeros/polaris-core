<?php

declare(strict_types=1);

namespace Polaris\Mcp\Tests\Functional;

use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Override;
use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Mcp\McpPlugin;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Exchange;
use Polaris\OAuth\OAuthPlugin;
use Polaris\OAuth\Tests\Functional\OAuthTestCase;
use Psr\Http\Message\ResponseInterface;

use function array_column;
use function dirname;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * WP4 acceptance 2, over HTTP: `POST /mcp` protected as an OAuth resource (401 with the metadata URL,
 * 403 with the missing scopes), the metadata route, and a principal's tools listed and called with
 * an access token the oauth plugin minted for `<baseUrl>/mcp` — each tool call's `structuredContent`
 * is what the HTTP route answers for the same request, asserted in the same test against the recorded
 * fixture. Replayed through every host with `POLARIS_HARNESS`.
 */
final class McpServerTest extends OAuthTestCase
{
    private const string VERSION = '2026-07-28';
    private const string METADATA = self::BASE . '/.well-known/oauth-protected-resource/mcp';

    #[Override]
    protected static function plugins(): array
    {
        return [new AuditPlugin(), new AdminPlugin(), new OAuthPlugin(
            baseUrl: self::BASE,
            consentUrl: self::CONSENT,
            httpClient: self::$http,
            requestFactory: new RequestFactory(),
            pollInterval: 0,
            audiences: [self::BASE . McpPlugin::PATH],
        ), new McpPlugin(self::BASE, new ServerRequestFactory(), new ResponseFactory(), new StreamFactory(), scopes: ['org.read'])];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    public function testTheProtectedResourceListsAndCallsTheToolsOfTheTokensUser(): void
    {
        // The metadata a challenged client is sent to.
        $metadata = $this->get('/.well-known/oauth-protected-resource/mcp');
        self::assertSame(200, $metadata->getStatusCode());
        self::assertStringContainsString('max-age=3600', $metadata->getHeaderLine('Cache-Control'));
        $document = $this->json($metadata);
        self::assertSame([self::BASE . '/mcp', [self::BASE], ['header']], [$document['resource'], $document['authorization_servers'], $document['bearer_methods_supported']]);
        self::assertContains('org.read', $document['scopes_supported']);

        // Without a token: the challenge names the metadata; a session token is not a token for this resource.
        $challenged = $this->mcp('tools/list', [], null);
        self::assertSame(401, $challenged->getStatusCode());
        self::assertSame('Bearer resource_metadata="' . self::METADATA . '"', $challenged->getHeaderLine('WWW-Authenticate'));
        self::assertSame('https://polaris.univeros.io/problems/mcp/unauthorized', $this->json($challenged)['type']);
        [, $session] = $this->login('ada@example.com');
        [$orgId, $session] = $this->organization($session, 'Acme');
        $refused = $this->mcp('tools/list', [], $session);
        self::assertSame(401, $refused->getStatusCode());
        self::assertStringStartsWith('Bearer error="invalid_token"', $refused->getHeaderLine('WWW-Authenticate'));

        // An access token for /mcp, by token exchange of Ada's session.
        $client = $this->client($session, $orgId, ['grant_types' => [Clients::GRANT_EXCHANGE], 'token_endpoint_auth_method' => 'client_secret_post']);
        $exchange = ['client_id' => $client['client_id'], 'client_secret' => $client['client_secret'], 'grant_type' => Clients::GRANT_EXCHANGE, 'subject_token' => $session, 'subject_token_type' => Exchange::TYPE_ACCESS_TOKEN, 'resource' => self::BASE . '/mcp'];
        $access = (string) $this->json($this->form('/oauth2/token', [...$exchange, 'scope' => 'org.read members.read']))['access_token'];
        self::assertSame(self::BASE . '/mcp', self::claims($access)['aud']);

        // The tools: every public route, the bearer routes within the delegated scopes, no admin route.
        $listed = $this->json($this->mcp('tools/list', [], $access));
        self::assertArrayHasKey('result', $listed, json_encode($listed, JSON_THROW_ON_ERROR));
        $names = array_column($listed['result']['tools'], 'name');
        foreach (['polaris.auth.login', 'polaris.auth.me', 'polaris.orgs.members.list', 'polaris.orgs.read', 'polaris.oauth.openid.configuration', 'polaris.oauth.consents.list'] as $name) {
            self::assertContains($name, $names);
        }
        foreach (['polaris.orgs.update', 'polaris.orgs.create', 'polaris.admin.users.list', 'polaris.auth.mfa.login.verify', 'polaris.schema.export'] as $name) {
            self::assertNotContains($name, $names);
        }

        // A tool call answers what the route answers, for the same request with the same token.
        $me = $this->call('polaris.auth.me', [], $access);
        self::assertFalse($me['isError']);
        self::assertSame(['status' => 200, 'body' => $this->json($this->authedGet('/auth/me', $access))], $me['structuredContent']);

        $members = $this->call('polaris.orgs.members.list', ['id' => $orgId], $access);
        self::assertFalse($members['isError']);
        self::assertSame(['status' => 200, 'body' => $this->json($this->authedGet('/orgs/' . $orgId . '/members', $access))], $members['structuredContent']);

        $discovery = $this->call('polaris.oauth.openid.configuration', [], $access);
        self::assertSame(['status' => 200, 'body' => $this->json($this->get('/.well-known/openid-configuration'))], $discovery['structuredContent']);

        // A route's refusal is an error result, not an exception; a tool not listed for the token is not callable.
        $other = '019aa7e0-0000-7000-8000-000000000000';
        $read = $this->call('polaris.orgs.read', ['id' => $other], $access);
        self::assertTrue($read['isError']);
        self::assertSame(['status' => 403, 'body' => $this->json($this->authedGet('/orgs/' . $other, $access))], $read['structuredContent']);
        $unlisted = $this->mcp('tools/call', ['name' => 'polaris.orgs.update', 'arguments' => ['id' => $orgId, 'name' => 'Evil']], $access, 'polaris.orgs.update');
        self::assertSame(400, $unlisted->getStatusCode());
        self::assertSame(-32602, $this->json($unlisted)['error']['code']);
        self::assertSame(403, $this->authedPatch('/orgs/' . $orgId, ['name' => 'Evil'], $access)->getStatusCode(), 'the route itself refuses the delegate too');

        // Short of the scope /mcp requires: 403 naming it.
        $narrow = (string) $this->json($this->form('/oauth2/token', [...$exchange, 'scope' => 'members.read']))['access_token'];
        $insufficient = $this->mcp('tools/list', [], $narrow);
        self::assertSame(403, $insufficient->getStatusCode());
        self::assertSame('Bearer error="insufficient_scope", scope="org.read", resource_metadata="' . self::METADATA . '"', $insufficient->getHeaderLine('WWW-Authenticate'));
        self::assertSame(['org.read'], $this->json($insufficient)['missing_scopes']);

        // The session-based protocol is rejected.
        $legacy = $this->handle($this->request('POST', '/mcp')->withHeader('Authorization', 'Bearer ' . $access)->withHeader('Mcp-Session-Id', '019aa7e0-0000-7000-8000-000000000000'));
        self::assertSame(400, $legacy->getStatusCode());
        self::assertSame('https://polaris.univeros.io/problems/mcp/legacy_protocol', $this->json($legacy)['type']);
    }

    /**
     * A tool call's result.
     *
     * @param array<string, mixed> $arguments
     * @return array<string, mixed>
     */
    private function call(string $name, array $arguments, string $access): array
    {
        $response = $this->mcp('tools/call', ['name' => $name, 'arguments' => $arguments === [] ? new \stdClass() : $arguments], $access, $name);
        $decoded = $this->json($response);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertArrayHasKey('result', $decoded, (string) $response->getBody());

        return $decoded['result'];
    }

    /**
     * One JSON-RPC request to /mcp in the 2026-07-28 profile: the version, method and name headers,
     * the `_meta` the profile requires.
     *
     * @param array<string, mixed> $params
     */
    private function mcp(string $method, array $params, ?string $access, ?string $name = null): ResponseInterface
    {
        $request = $this->request('POST', '/mcp')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withHeader('MCP-Protocol-Version', self::VERSION)
            ->withHeader('Mcp-Method', $method);
        if ($name !== null) {
            $request = $request->withHeader('Mcp-Name', $name);
        }
        if ($access !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $access);
        }
        $body = ['jsonrpc' => '2.0', 'id' => 1, 'method' => $method, 'params' => [
            ...$params,
            '_meta' => ['io.modelcontextprotocol/protocolVersion' => self::VERSION, 'io.modelcontextprotocol/clientCapabilities' => new \stdClass()],
        ]];
        $request->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR));
        $request->getBody()->rewind();

        return $this->handle($request);
    }
}

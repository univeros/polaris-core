<?php

declare(strict_types=1);

namespace Polaris\Mcp\Tests;

use DateTimeImmutable;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Override;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Admin\Tests\Support\MutableClock;
use Polaris\Mcp\Jose;
use Polaris\Mcp\McpException;
use Polaris\Mcp\Protect\DpopProof;
use Polaris\Mcp\Protect\Jwks;
use Polaris\Mcp\Protect\McpProtectedResource;
use Polaris\Mcp\Protect\TokenVerifier;
use Polaris\Mcp\Tests\Support\Issuer;
use Polaris\OAuth\Tests\Support\FakeHttp;
use Polaris\OAuth\Tests\Support\Keys;
use Polaris\Support\InMemoryCache;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function json_decode;
use function json_encode;
use function time;

/**
 * WP4 acceptance 1: the protected resource accepts a valid token, answers 401 with `resource_metadata`
 * without one, 403 `insufficient_scope` with the missing scopes, and works against a remote issuer
 * (its JWKS fetched through a PSR-18 client and cached); DPoP binding, legacy rejection, the metadata.
 */
#[CoversClass(McpProtectedResource::class)]
#[CoversClass(TokenVerifier::class)]
#[CoversClass(DpopProof::class)]
#[CoversClass(Jwks::class)]
#[CoversClass(Jose::class)]
#[CoversClass(McpException::class)]
final class ProtectedResourceTest extends TestCase
{
    private const string RESOURCE = 'https://mcp.polaris.test/mcp';
    private const string METADATA = 'https://mcp.polaris.test/.well-known/oauth-protected-resource/mcp';

    private Issuer $issuer;
    private InMemoryCache $cache;
    private MutableClock $clock;

    protected function setUp(): void
    {
        $this->issuer = new Issuer();
        $this->cache = new InMemoryCache();
        $this->clock = new MutableClock(new DateTimeImmutable('@' . time()));
    }

    public function testAValidTokenReachesTheHandlerWithItsClaims(): void
    {
        $response = $this->through($this->local(), $this->request($this->issuer->token()));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('ada', $this->body($response)['sub']);
    }

    public function testWithoutATokenTheChallengeNamesTheMetadata(): void
    {
        $response = $this->through($this->local(), $this->request());
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer resource_metadata="' . self::METADATA . '"', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'));
        self::assertSame('https://polaris.univeros.io/problems/mcp/unauthorized', $this->body($response)['type']);
        self::assertSame('mcp_unauthorized', $this->body($response)['error']);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testABadTokenIsInvalidToken(): void
    {
        $stranger = new Issuer(alternate: true);
        foreach (
            [
            'another resource' => $this->issuer->token(['aud' => 'https://other.test']),
            'expired' => $this->issuer->token(['exp' => time() - 120]),
            'not yet valid' => $this->issuer->token(['nbf' => time() + 120]),
            'another issuer' => $this->issuer->token(['iss' => 'https://other.test']),
            'a stranger\'s signature' => $stranger->token(),
            'an unknown kid' => $this->issuer->token(kid: 'other'),
            'no expiry' => $this->issuer->token(['exp' => null]),
            'not a JWT' => 'opaque',
            ] as $case => $token
        ) {
            $response = $this->through($this->local(), $this->request($token));
            self::assertSame(401, $response->getStatusCode(), $case);
            self::assertStringStartsWith('Bearer error="invalid_token", error_description="', $response->getHeaderLine('WWW-Authenticate'), $case);
            self::assertStringEndsWith('resource_metadata="' . self::METADATA . '"', $response->getHeaderLine('WWW-Authenticate'), $case);
        }
        // The issuer itself is an accepted audience only when configured so (Polaris's own /mcp).
        self::assertSame(401, $this->through($this->local(), $this->request($this->issuer->token(['aud' => Issuer::URL])))->getStatusCode());
        self::assertSame(200, $this->through($this->local(audiences: [self::RESOURCE, Issuer::URL]), $this->request($this->issuer->token(['aud' => [Issuer::URL, 'x']])))->getStatusCode());
    }

    public function testAMissingScopeIsInsufficientScopeNamingTheMissingOnes(): void
    {
        $response = $this->through($this->local(scopes: ['org.read', 'deploy', 'members.read']), $this->request($this->issuer->token(['scope' => 'org.read openid'])));
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('Bearer error="insufficient_scope", scope="deploy members.read", resource_metadata="' . self::METADATA . '"', $response->getHeaderLine('WWW-Authenticate'));
        self::assertSame(['deploy', 'members.read'], $this->body($response)['missing_scopes']);
        self::assertSame('https://polaris.univeros.io/problems/mcp/insufficient_scope', $this->body($response)['type']);
        self::assertSame(200, $this->through($this->local(scopes: ['org.read']), $this->request($this->issuer->token(['scope' => ['org.read']])))->getStatusCode(), 'a scope list');
    }

    public function testADpopBoundTokenNeedsAProofForTheRequestByItsKey(): void
    {
        $keys = new Keys();
        $token = $this->issuer->token(['cnf' => ['jkt' => $keys->dpopThumbprint()]]);
        $proof = fn(string $url = self::RESOURCE, ?string $jti = null): string => $keys->dpopProof('POST', $url, $token, $jti);

        self::assertSame(401, $this->through($this->local(), $this->request($token))->getStatusCode(), 'bound token with the Bearer scheme');
        self::assertSame(401, $this->through($this->local(), $this->request($token, 'DPoP'))->getStatusCode(), 'no proof');
        self::assertSame(401, $this->through($this->local(), $this->request($token, 'DPoP', $proof('https://mcp.polaris.test/other')))->getStatusCode(), 'a proof for another URL');
        self::assertSame(401, $this->through($this->local(), $this->request($token, 'DPoP', $keys->dpopProof('POST', self::RESOURCE)))->getStatusCode(), 'a proof without ath');
        self::assertSame(401, $this->through($this->local(), $this->request($token, 'DPoP', $keys->dpopProof('POST', self::RESOURCE, $token, iat: time() - 600)))->getStatusCode(), 'a stale proof');
        self::assertSame(401, $this->through($this->local(), $this->request($token, 'DPoP', (new Keys())->dpopProof('POST', self::RESOURCE, $token)))->getStatusCode(), 'another key');
        $response = $this->through($this->local(), $this->request($token, 'DPoP', $proof(jti: 'once')));
        self::assertSame(200, $response->getStatusCode(), 'a good proof');
        self::assertSame($keys->dpopThumbprint(), $this->body($response)['cnf']['jkt']);
        self::assertSame(401, $this->through($this->local(), $this->request($token, 'DPoP', $proof(jti: 'once')))->getStatusCode(), 'the same proof again');
        self::assertSame(200, $this->through($this->local(), $this->request($token, 'DPoP', $proof()))->getStatusCode(), 'a fresh one');
        self::assertSame(401, $this->through($this->local(), $this->request($this->issuer->token(), 'DPoP', $proof()))->getStatusCode(), 'a bearer token with the DPoP scheme');
    }

    public function testAgainstARemoteIssuerTheKeysAreFetchedOnceAndCached(): void
    {
        $http = new FakeHttp();
        $http->publish(Issuer::JWKS, $this->issuer->jwks());
        $middleware = $this->remote($http);

        self::assertSame(200, $this->through($middleware, $this->request($this->issuer->token()))->getStatusCode());
        self::assertSame(200, $this->through($middleware, $this->request($this->issuer->token()))->getStatusCode());
        self::assertSame([Issuer::JWKS], $http->fetched, 'the set is cached');
        self::assertSame(401, $this->through($middleware, $this->request((new Issuer(alternate: true))->token()))->getStatusCode(), 'a stranger\'s signature');
        // An unknown kid fetches the set once more (a rotation); still unknown, the token is refused.
        self::assertSame(401, $this->through($middleware, $this->request($this->issuer->token(kid: 'rotated')))->getStatusCode());
        self::assertCount(2, $http->fetched);
        // Another unknown kid within a minute fetches nothing: an unauthenticated JWT is no refetch amplifier.
        $http->publish(Issuer::JWKS, $this->issuer->jwks('rotated'));
        foreach (['rotated', 'other', 'rotated'] as $kid) {
            self::assertSame(401, $this->through($middleware, $this->request($this->issuer->token(kid: $kid)))->getStatusCode(), 'unknown kid ' . $kid . ' within the interval');
        }
        self::assertCount(2, $http->fetched, 'no refetch within ' . Jwks::MIN_REFETCH_INTERVAL . ' seconds');
        $this->clock->advance('+' . Jwks::MIN_REFETCH_INTERVAL . ' seconds');
        self::assertSame(200, $this->through($middleware, $this->request($this->issuer->token(kid: 'rotated')))->getStatusCode(), 'the rotated key, once published and the interval over');
        self::assertCount(3, $http->fetched);

        // An issuer that cannot be reached, or answers junk, refuses the token with a generic reason.
        $down = $this->remote(new FakeHttp(), cache: new InMemoryCache());
        $response = $this->through($down, $this->request($this->issuer->token()));
        self::assertSame(401, $response->getStatusCode());
        self::assertStringContainsString('could not be verified', $this->body($response)['detail']);
        $this->expectException(\LogicException::class);
        new Jwks('http://issuer.test/jwks', $http, new RequestFactory(), $this->cache);
    }

    public function testTheSessionBasedProtocolIsRejectedUnlessAllowed(): void
    {
        $token = $this->issuer->token();
        foreach (
            [
            'a session header' => $this->request($token)->withHeader('Mcp-Session-Id', '019aa7e0-0000-7000-8000-000000000000'),
            'an older version' => $this->request($token)->withHeader('MCP-Protocol-Version', '2025-11-25'),
            'an initialize call' => $this->request($token, body: ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize', 'params' => []]),
            ] as $case => $request
        ) {
            $response = $this->through($this->local(), $request);
            self::assertSame(400, $response->getStatusCode(), $case);
            self::assertSame('https://polaris.univeros.io/problems/mcp/legacy_protocol', $this->body($response)['type'], $case);
            self::assertSame('2026-07-28', $this->body($response)['protocol_version'], $case);
            self::assertSame(200, $this->through($this->local(legacy: 'allow'), $request)->getStatusCode(), $case . ', allowed');
        }
        self::assertSame(200, $this->through($this->local(), $this->request($token)->withHeader('MCP-Protocol-Version', '2026-07-28'))->getStatusCode());
        // The body stays readable for the server behind.
        $request = $this->request($token, body: ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list']);
        $this->through($this->local(), $request);
        self::assertStringContainsString('tools', (string) $request->getBody());
    }

    public function testItServesItsOwnMetadata(): void
    {
        $middleware = $this->local(scopes: ['org.read'], name: 'Polaris');
        $response = $this->through($middleware, (new ServerRequestFactory())->createServerRequest('GET', self::METADATA));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('public, max-age=3600', $response->getHeaderLine('Cache-Control'));
        self::assertSame([
            'resource' => self::RESOURCE,
            'authorization_servers' => [Issuer::URL],
            'scopes_supported' => ['org.read'],
            'bearer_methods_supported' => ['header'],
            'dpop_signing_alg_values_supported' => Jose::ALGORITHMS,
            'resource_name' => 'Polaris',
        ], $this->body($response));
        self::assertSame(self::METADATA, $middleware->metadataUrl());
        self::assertSame('https://app.test/.well-known/oauth-protected-resource', $this->local(resource: 'https://app.test/')->metadataUrl(), 'a resource at the origin');
        self::assertSame('https://app.test/.well-known/oauth-protected-resource/auth/mcp', $this->local(resource: 'https://app.test/auth/mcp')->metadataUrl(), 'RFC 9728 inserts the path');
        $this->expectException(\LogicException::class);
        $this->local(legacy: 'maybe');
    }

    public function testTheJoseHelpers(): void
    {
        // RFC 7638 §3.1's example thumbprint.
        $jwk = ['kty' => 'RSA', 'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw', 'e' => 'AQAB', 'alg' => 'RS256', 'kid' => '2011-04-29'];
        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', Jose::thumbprint($jwk));
        self::assertNull(Jose::thumbprint(['kty' => 'oct', 'k' => 'x']));
        self::assertNull(Jose::header('not.a-jwt'));
        self::assertSame('f', Jose::base64UrlDecode(Jose::base64UrlEncode('f')));
    }

    /**
     * @param list<string>|null $audiences
     * @param list<string> $scopes
     */
    private function local(?array $audiences = null, array $scopes = [], string $legacy = 'reject', ?string $name = null, string $resource = self::RESOURCE): McpProtectedResource
    {
        $verifier = TokenVerifier::withKeys(Issuer::URL, $audiences ?? [$resource], [Issuer::KID => $this->issuer->publicKey()], $this->clock);

        return new McpProtectedResource($resource, $verifier, new ResponseFactory(), $this->cache, $this->clock, $scopes, $legacy, resourceName: $name, streams: new StreamFactory());
    }

    private function remote(FakeHttp $http, ?InMemoryCache $cache = null): McpProtectedResource
    {
        $jwks = new Jwks(Issuer::JWKS, $http, new RequestFactory(), $cache ?? $this->cache, clock: $this->clock);

        return new McpProtectedResource(self::RESOURCE, TokenVerifier::withJwks(Issuer::URL, [self::RESOURCE], $jwks, $this->clock), new ResponseFactory(), $this->cache, $this->clock);
    }

    /**
     * @param array<string, mixed>|null $body
     */
    private function request(?string $token = null, string $scheme = 'Bearer', ?string $proof = null, ?array $body = null): ServerRequestInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', self::RESOURCE)->withHeader('Content-Type', 'application/json');
        if ($token !== null) {
            $request = $request->withHeader('Authorization', $scheme . ' ' . $token);
        }
        if ($proof !== null) {
            $request = $request->withHeader('DPoP', $proof);
        }
        $request->getBody()->write(json_encode($body ?? ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list', 'params' => []], JSON_THROW_ON_ERROR));
        $request->getBody()->rewind();

        return $request;
    }

    /**
     * The middleware in front of a handler answering the verified claims.
     */
    private function through(McpProtectedResource $middleware, ServerRequestInterface $request): ResponseInterface
    {
        return $middleware->process($request, new class implements RequestHandlerInterface {
            #[Override]
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $response = (new ResponseFactory())->createResponse(200)->withHeader('Content-Type', 'application/json');
                $response->getBody()->write(json_encode($request->getAttribute(McpProtectedResource::CLAIMS), JSON_THROW_ON_ERROR));

                return $response;
            }
        });
    }

    /**
     * @return array<string, mixed>
     */
    private function body(ResponseInterface $response): array
    {
        return (array) json_decode((string) $response->getBody(), true);
    }
}

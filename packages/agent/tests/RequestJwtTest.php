<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Polaris\Agent\AgentKey;
use Polaris\Agent\RequestJwt;
use Polaris\Agent\Tests\Support\Fixtures;
use Throwable;

use function hash;

final class RequestJwtTest extends TestCase
{
    public function testTheRequestJwtCarriesTheProtocolsClaimsForTheExactUrlAndBody(): void
    {
        $key = AgentKey::generate();
        $body = '{"capability":"demo.echo","arguments":{"hello":"world"}}';
        $jwt = RequestJwt::sign($key, 'agent-1', 'post', 'https://auth.polaris.test/agents/execute?x=1#f', $body, now: static fn(): int => 1760090400);
        ['header' => $header, 'claims' => $claims] = Fixtures::decode($jwt);
        self::assertSame(['typ' => 'agent+jwt', 'alg' => 'ES256', 'kid' => $key->kid], $header);
        self::assertSame(['agent-1', 'https://auth.polaris.test/agents/execute', 1760090400, 1760090460, 'POST', 'https://auth.polaris.test/agents/execute', AgentKey::base64Url(hash('sha256', $body, true))], [$claims['sub'], $claims['aud'], $claims['iat'], $claims['exp'], $claims['htm'], $claims['htu'], $claims['body_hash']]);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{22}$/', $claims['jti']);
        self::assertArrayNotHasKey('capabilities', $claims);
        JWT::$timestamp = 1760090401;
        self::assertSame('agent-1', JWT::decode($jwt, JWK::parseKey($key->publicJwk))->sub, 'verifies with the public JWK');
        JWT::$timestamp = null;
    }

    public function testEdDsaCapabilitiesTtlAndNoBodyHashWithoutABody(): void
    {
        $key = AgentKey::generate('EdDSA');
        $jwt = RequestJwt::sign($key, 'agent-1', 'GET', 'https://auth.polaris.test/agents/session', null, ['demo.echo'], 300);
        ['header' => $header, 'claims' => $claims] = Fixtures::decode($jwt);
        self::assertSame('EdDSA', $header['alg']);
        self::assertSame(['demo.echo'], $claims['capabilities']);
        self::assertArrayNotHasKey('body_hash', $claims);
        self::assertSame(300, $claims['exp'] - $claims['iat']);
        self::assertSame('agent-1', JWT::decode($jwt, JWK::parseKey($key->publicJwk))->sub);
        self::assertNotSame(Fixtures::decode(RequestJwt::sign($key, 'a', 'GET', 'https://x.test/', null))['claims']['jti'], $claims['jti']);
    }

    public function testItNeverSignsForLongerThanTheServerAcceptsAndAnotherKeyDoesNotVerify(): void
    {
        $key = AgentKey::generate();
        try {
            RequestJwt::sign($key, 'a', 'GET', 'https://x.test/', null, ttl: 301);
            self::fail('301 seconds');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('300', $exception->getMessage());
        }
        $this->expectException(Throwable::class);
        JWT::decode(RequestJwt::sign($key, 'a', 'GET', 'https://x.test/', null), JWK::parseKey(AgentKey::generate()->publicJwk));
    }

    public function testTheClientAssertionNamesTheAgentAndTheTokenEndpoint(): void
    {
        $key = AgentKey::generate();
        $assertion = RequestJwt::assertion($key, 'agent-1', 'https://auth.polaris.test/oauth2/token', static fn(): int => 1760090400);
        ['header' => $header, 'claims' => $claims] = Fixtures::decode($assertion);
        self::assertSame(['typ' => 'JWT', 'alg' => 'ES256', 'kid' => $key->kid], $header);
        self::assertSame(['agent-1', 'agent-1', 'https://auth.polaris.test/oauth2/token', 1760090400, 1760090700], [$claims['iss'], $claims['sub'], $claims['aud'], $claims['iat'], $claims['exp']]);
    }
}

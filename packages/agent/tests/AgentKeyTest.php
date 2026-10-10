<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Polaris\Agent\AgentKey;
use Polaris\Agent\Tests\Support\Fixtures;

final class AgentKeyTest extends TestCase
{
    public function testAnEs256KeyHasItsThumbprintAsKidAndNoPrivatePartInItsPublicJwk(): void
    {
        $key = AgentKey::generate();
        self::assertSame('ES256', $key->alg);
        self::assertSame(['kty' => 'EC', 'crv' => 'P-256', 'alg' => 'ES256', 'kid' => $key->kid, 'use' => 'sig'], array_diff_key($key->publicJwk, ['x' => 1, 'y' => 1]));
        self::assertArrayNotHasKey('d', $key->publicJwk);
        self::assertSame(AgentKey::thumbprint(['kty' => 'EC', 'crv' => 'P-256', 'x' => $key->publicJwk['x'], 'y' => $key->publicJwk['y']]), $key->kid);
        $jws = $key->sign(['sub' => 'a'], ['typ' => 'agent+jwt']);
        self::assertSame(['typ' => 'agent+jwt', 'alg' => 'ES256', 'kid' => $key->kid], Fixtures::decode($jws)['header']);
        self::assertSame('a', JWT::decode($jws, JWK::parseKey($key->publicJwk))->sub);
    }

    public function testAnEdDsaKeyIsEd25519WithAGivenKid(): void
    {
        $key = AgentKey::generate('EdDSA', 'my-agent-key');
        self::assertSame(['OKP', 'Ed25519', 'EdDSA', 'my-agent-key'], [$key->publicJwk['kty'], $key->publicJwk['crv'], $key->publicJwk['alg'], $key->publicJwk['kid']]);
        self::assertArrayNotHasKey('y', $key->publicJwk);
        self::assertSame('a', JWT::decode($key->sign(['sub' => 'a']), JWK::parseKey($key->publicJwk))->sub);
    }

    public function testAKeyRoundTripsThroughItsStoredForm(): void
    {
        foreach (['ES256', 'EdDSA'] as $alg) {
            $key = AgentKey::generate($alg);
            $again = AgentKey::fromArray($key->toArray());
            self::assertSame($key->publicJwk, $again->publicJwk, $alg);
            self::assertSame($key->kid, $again->kid, $alg);
        }
        $this->expectException(InvalidArgumentException::class);
        AgentKey::fromArray(['alg' => 'ES256']);
    }

    public function testTheThumbprintFollowsRfc7638(): void
    {
        $n = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', AgentKey::thumbprint(['kty' => 'RSA', 'e' => 'AQAB', 'n' => $n]));
    }
}

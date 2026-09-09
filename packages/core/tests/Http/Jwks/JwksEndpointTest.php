<?php

declare(strict_types=1);

namespace Polaris\Tests\Http\Jwks;

use PHPUnit\Framework\TestCase;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Http\Input;
use Polaris\Http\Jwks\JwksEndpoint;
use Polaris\Tests\Support\TestKeys;

/**
 * The JWKS endpoint serves a `200` JWK Set whose single key is the configured public
 * key, advertised under the configured `kid` and signing algorithm.
 */
final class JwksEndpointTest extends TestCase
{
    public function testServesThePublicKeyByKid(): void
    {
        $keys = TestKeys::rsa();
        $secrets = new Secrets('app-key', $keys['private'], $keys['public'], 'kid-42');
        $config = AuthConfig::fromArray(['issuer' => 'https://auth.polaris.test']);

        $result = (new JwksEndpoint($secrets, $config))(new Input());

        self::assertSame(200, $result->status);

        $output = $result->body;
        self::assertIsArray($output['keys']);
        $jwk = $output['keys'][0];
        self::assertIsArray($jwk);
        self::assertSame('kid-42', $jwk['kid']);
        self::assertSame('RS256', $jwk['alg']);
        self::assertSame('RSA', $jwk['kty']);
    }
}

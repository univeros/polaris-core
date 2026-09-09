<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Container\Container;
use Polaris\Contract\TokenConfigurationInterface;
use Altair\Http\Contracts\TokenFactoryInterface as AltairTokenFactory;
use Polaris\Contract\TokenFactoryInterface;
use Polaris\Contract\TokenGeneratorInterface;
use Polaris\Contract\TokenParserInterface;
use Polaris\Contract\TokenValidatorInterface;
use Polaris\Support\SystemClock;
use Polaris\Token\TokenConfiguration;
use Psr\Clock\ClockInterface;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Exception\InvalidConfigException;
use Univeros\Polaris\Http\Jwks\JwksDomain;
use Polaris\Token\JwtSignerFactory;
use Polaris\Token\PolarisTokenFactory;
use Polaris\Token\PolarisTokenGenerator;
use Polaris\Token\PolarisTokenParser;
use Polaris\Token\PolarisTokenValidator;

/**
 * Wires the JWT machinery: the token configuration, the Polaris generator, and the
 * parser/validator/factory that verify tokens, plus the public JWKS document.
 */
final class TokenBindings
{
    public function apply(Container $container, AuthConfig $authConfig, Secrets $secrets): void
    {
        $this->bindTokens($container, $authConfig, $secrets);
    }

    /**
     * Bind the JWT machinery: a {@see TokenConfigurationInterface} derived from
     * {@see AuthConfig} (issuer/audience/ttl/signer) and {@see Secrets} (keys), the
     * Polaris generator (full claim set + `kid` header), and the parser/validator/factory
     * that verify tokens against the public key. Issuance time (`iat`/`exp`/`nbf`) is
     * derived from the injected {@see ClockInterface} at mint time, not from the
     * configuration, so the configuration carries only static values.
     */
    private function bindTokens(Container $container, AuthConfig $authConfig, Secrets $secrets): void
    {
        $container->singleton(ClockInterface::class, SystemClock::class);

        $container->singleton(
            TokenConfigurationInterface::class,
            static function () use ($authConfig, $secrets): TokenConfiguration {
                $publicKey = $secrets->jwtPublicKey;
                $issuer = $authConfig->issuer;
                if ($publicKey === '' || $issuer === '') {
                    throw new InvalidConfigException('A JWT public key and issuer are required to mint tokens.');
                }

                return new TokenConfiguration(
                    $publicKey,
                    $authConfig->accessToken->ttl,
                    JwtSignerFactory::create($authConfig->accessToken->signer),
                    $issuer,
                    null,
                    $secrets->jwtPrivateKey,
                    $authConfig->audience,
                );
            },
        );

        $keyId = $secrets->jwtKid;
        $container->singleton(
            TokenGeneratorInterface::class,
            static fn(TokenConfigurationInterface $config, ClockInterface $clock): PolarisTokenGenerator
                => new PolarisTokenGenerator($config, $clock, $keyId),
        );

        $container->singleton(TokenParserInterface::class, PolarisTokenParser::class);
        $container->singleton(TokenValidatorInterface::class, PolarisTokenValidator::class);
        $container->singleton(TokenFactoryInterface::class, PolarisTokenFactory::class);
        $container->singleton(
            AltairTokenFactory::class,
            static fn(TokenFactoryInterface $factory): AltairTokenFactoryBridge => new AltairTokenFactoryBridge($factory),
        );
        $container->singleton(JwksDomain::class);
    }
}

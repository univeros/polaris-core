<?php

declare(strict_types=1);

namespace Polaris\Token;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Override;
use Polaris\Contract\TokenConfigurationInterface;
use Polaris\Contract\TokenInterface;
use Polaris\Contract\TokenParserInterface;
use Polaris\Exception\InvalidTokenException;
use Polaris\Support\SystemClock;
use Psr\Clock\ClockInterface;

/**
 * Parses and verifies a JWT with lcobucci/jwt: signature, issuer, validity window, and audience when configured.
 */
class LcobucciTokenParser implements TokenParserInterface
{
    private readonly ClockInterface $clock;

    public function __construct(
        protected TokenConfigurationInterface $config,
        ?ClockInterface $clock = null,
    ) {
        $this->clock = $clock ?? new SystemClock();
    }

    #[Override]
    public function parse(string $token): TokenInterface
    {
        if ($token === '') {
            throw new InvalidTokenException('Could not parse the authorization token.');
        }

        $configuration = $this->buildConfiguration();
        $parsed = $this->parseToken($configuration, $token);

        try {
            $configuration->validator()->assert($parsed, ...$this->constraints($configuration));
        } catch (RequiredConstraintsViolated $violated) {
            throw new InvalidTokenException($violated->getMessage(), 0, $violated);
        }

        return new Token($token, $parsed->claims()->all());
    }

    /**
     * @return list<Constraint>
     */
    private function constraints(Configuration $configuration): array
    {
        $constraints = [
            new SignedWith($this->config->getSigner(), $configuration->verificationKey()),
            new IssuedBy($this->config->getIssuer()),
            new LooseValidAt($this->clock),
        ];

        $audience = $this->config->getAudience();
        if ($audience !== null && $audience !== '') {
            $constraints[] = new PermittedFor($audience);
        }

        return $constraints;
    }

    private function buildConfiguration(): Configuration
    {
        $verificationKey = InMemory::plainText($this->config->getPublicKey());

        return Configuration::forAsymmetricSigner($this->config->getSigner(), $verificationKey, $verificationKey);
    }

    private function parseToken(Configuration $configuration, string $token): UnencryptedToken
    {
        try {
            $parsed = $configuration->parser()->parse($token);
        } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $exception) {
            throw new InvalidTokenException('Could not parse the authorization token.', 0, $exception);
        }

        if (!$parsed instanceof UnencryptedToken) {
            throw new InvalidTokenException('Could not parse the authorization token.');
        }

        return $parsed;
    }
}

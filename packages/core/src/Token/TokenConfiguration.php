<?php

declare(strict_types=1);

namespace Polaris\Token;

use InvalidArgumentException;
use Lcobucci\JWT\Signer;
use Override;
use Polaris\Contract\TokenConfigurationInterface;

use function time;

final readonly class TokenConfiguration implements TokenConfigurationInterface
{
    private int $timestamp;

    public function __construct(
        private string $publicKey,
        private int $ttl,
        private Signer $signer,
        private string $issuer,
        ?int $timestamp = null,
        private ?string $privateKey = null,
        private ?string $audience = null,
    ) {
        if ($publicKey === '') {
            throw new InvalidArgumentException('The public key must be a non-empty string.');
        }
        if ($issuer === '') {
            throw new InvalidArgumentException('The issuer must be a non-empty string.');
        }
        $this->timestamp = $timestamp ?: time();
    }

    #[Override]
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    #[Override]
    public function getTtl(): int
    {
        return $this->ttl;
    }

    #[Override]
    public function getSigner(): Signer
    {
        return $this->signer;
    }

    #[Override]
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    #[Override]
    public function getAudience(): ?string
    {
        return $this->audience;
    }

    #[Override]
    public function getTimestamp(): int
    {
        return $this->timestamp;
    }

    #[Override]
    public function getPrivateKey(): ?string
    {
        return $this->privateKey;
    }

    #[Override]
    public function getExpirationTimestamp(): int
    {
        return $this->timestamp + $this->ttl;
    }
}

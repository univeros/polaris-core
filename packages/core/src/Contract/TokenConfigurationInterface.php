<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Lcobucci\JWT\Signer;

interface TokenConfigurationInterface
{
    public function getPublicKey(): string;

    public function getTtl(): int;

    public function getSigner(): Signer;

    public function getIssuer(): string;

    public function getAudience(): ?string;

    public function getTimestamp(): int;

    public function getExpirationTimestamp(): int;

    public function getPrivateKey(): ?string;
}

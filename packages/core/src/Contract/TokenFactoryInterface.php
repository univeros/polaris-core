<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Polaris\Exception\AuthorizationTokenException;
use Polaris\Exception\InvalidTokenException;

interface TokenFactoryInterface
{
    /**
     * @throws InvalidTokenException
     */
    public function fromTokenString(string $token): TokenInterface;

    /**
     * @param array<int|string, mixed> $credentials
     * @throws AuthorizationTokenException
     */
    public function fromCredentials(array $credentials): TokenInterface;
}

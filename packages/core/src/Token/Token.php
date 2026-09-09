<?php

declare(strict_types=1);

namespace Polaris\Token;

use Override;
use Polaris\Contract\TokenInterface;

final class Token implements TokenInterface
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(private readonly string $token, private readonly array $metadata)
    {
    }

    #[Override]
    public function getToken(): string
    {
        return $this->token;
    }

    #[Override]
    public function getMetadata(?string $key = null): mixed
    {
        return $key !== null ? ($this->metadata[$key] ?? null) : $this->metadata;
    }
}

<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Http\Contracts\TokenInterface as AltairToken;
use Override;
use Polaris\Contract\TokenInterface;

/**
 * Univeros glue (gone in WP7): one token object that satisfies both the framework's
 * token contract, which its authentication middleware stores on the request, and the
 * Polaris contract the services expect.
 */
final class DualToken implements AltairToken, TokenInterface
{
    public function __construct(private readonly TokenInterface $token)
    {
    }

    #[Override]
    public function getToken(): string
    {
        return $this->token->getToken();
    }

    #[Override]
    public function getMetadata(?string $key = null): mixed
    {
        return $this->token->getMetadata($key);
    }
}

<?php

declare(strict_types=1);

namespace Univeros\Polaris\Bootstrap;

use Altair\Http\Contracts\IdentityProviderInterface as AltairIdentityProvider;
use Override;
use Polaris\Contract\IdentityProviderInterface;

/**
 * Univeros glue (gone in WP7): the Polaris identity provider under the framework's contract,
 * for the framework's credential validator.
 */
final class AltairIdentityProviderBridge implements AltairIdentityProvider
{
    public function __construct(private readonly IdentityProviderInterface $identities)
    {
    }

    #[Override]
    public function findOneBy(array $criteria): ?array
    {
        return $this->identities->findOneBy($criteria);
    }
}

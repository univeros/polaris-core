<?php

declare(strict_types=1);

namespace Polaris\Contract;

interface IdentityProviderInterface
{
    /**
     * @param array<string, mixed> $criteria
     * @return array<string, mixed>|null
     */
    public function findOneBy(array $criteria): ?array;
}

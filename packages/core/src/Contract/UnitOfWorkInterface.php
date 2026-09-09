<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * Collects writes and applies them on {@see flush()}.
 */
interface UnitOfWorkInterface
{
    public function persist(object $entity): void;

    public function remove(object $entity): void;

    public function flush(): void;
}

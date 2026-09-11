<?php

declare(strict_types=1);

namespace Polaris\Plugin;

use Override;
use Polaris\Contract\Plugin;
use Polaris\Wiring\Graph;

/**
 * Empty defaults for every optional part of {@see Plugin}: a plugin overrides what it has.
 */
abstract class AbstractPlugin implements Plugin
{
    #[Override]
    public function schema(): array
    {
        return [];
    }

    #[Override]
    public static function manifestDirectory(): ?string
    {
        return null;
    }

    #[Override]
    public function services(): array
    {
        return [];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        return [];
    }

    #[Override]
    public function permissions(): array
    {
        return [];
    }
}

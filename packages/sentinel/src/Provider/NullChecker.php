<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use Override;
use SensitiveParameter;

final class NullChecker implements BreachChecker
{
    #[Override]
    public function isBreached(#[SensitiveParameter] string $password): bool
    {
        return false;
    }
}

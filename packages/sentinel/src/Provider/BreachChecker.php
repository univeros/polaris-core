<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use SensitiveParameter;

/**
 * Whether a password appears in a known breach corpus.
 */
interface BreachChecker
{
    public function isBreached(#[SensitiveParameter] string $password): bool;
}

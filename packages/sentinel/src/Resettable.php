<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

/**
 * A signal whose counters an operator can clear for an identifier (an email, an IP).
 */
interface Resettable
{
    public function reset(string $identifier): void;
}

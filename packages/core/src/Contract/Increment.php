<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * An update value meaning `column = column + $by`, evaluated by the database so concurrent
 * writers cannot lose increments.
 */
final readonly class Increment
{
    public function __construct(public int $by = 1)
    {
    }
}

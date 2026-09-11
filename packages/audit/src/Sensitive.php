<?php

declare(strict_types=1);

namespace Polaris\Audit;

/**
 * Wraps a value an emitting package wants redacted whatever its key: `['answer' => new Sensitive($x)]`.
 */
final readonly class Sensitive
{
    public function __construct(public mixed $value)
    {
    }
}

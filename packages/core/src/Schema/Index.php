<?php

declare(strict_types=1);

namespace Polaris\Schema;

/**
 * @param list<string> $columns
 */
final readonly class Index
{
    /**
     * @param list<string> $columns
     */
    public function __construct(public array $columns, public bool $unique, public string $name)
    {
    }
}

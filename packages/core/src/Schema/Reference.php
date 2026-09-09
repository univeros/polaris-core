<?php

declare(strict_types=1);

namespace Polaris\Schema;

/**
 * A foreign key.
 */
final readonly class Reference
{
    /**
     * @param list<string> $columns
     * @param list<string> $referencedColumns
     */
    public function __construct(
        public array $columns,
        public string $referencedTable,
        public array $referencedColumns,
        public string $onDelete = 'CASCADE',
        public string $onUpdate = 'CASCADE',
    ) {
    }
}

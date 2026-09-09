<?php

declare(strict_types=1);

namespace Polaris\Schema;

use InvalidArgumentException;

use function array_filter;
use function array_values;
use function implode;
use function sprintf;

/**
 * One table, the model class stored in it, and the property/column mapping. Immutable.
 */
final readonly class Model
{
    /**
     * @param class-string $class
     * @param list<Field> $fields
     * @param list<Index> $indexes
     * @param list<Reference> $references
     */
    private function __construct(
        public string $table,
        public string $class,
        public array $fields,
        public array $indexes,
        public array $references,
    ) {
    }

    /**
     * @param class-string $class
     * @param list<Field> $fields
     */
    public static function table(string $table, string $class, array $fields): self
    {
        return new self($table, $class, $fields, [], []);
    }

    /**
     * @param list<string> $columns
     */
    public function unique(array $columns, ?string $name = null): self
    {
        return $this->withIndex(new Index($columns, true, $name ?? $this->indexName($columns, 'unique')));
    }

    /**
     * @param list<string> $columns
     */
    public function index(array $columns, ?string $name = null): self
    {
        return $this->withIndex(new Index($columns, false, $name ?? $this->indexName($columns, 'index')));
    }

    /**
     * @param list<string> $columns
     * @param list<string> $referencedColumns
     */
    public function references(array $columns, string $table, array $referencedColumns, string $onDelete = 'CASCADE', string $onUpdate = 'CASCADE'): self
    {
        return new self($this->table, $this->class, $this->fields, $this->indexes, [
            ...$this->references,
            new Reference($columns, $table, $referencedColumns, $onDelete, $onUpdate),
        ]);
    }

    /**
     * @return list<Field>
     */
    public function primaryKey(): array
    {
        return array_values(array_filter($this->fields, static fn(Field $field): bool => $field->primary));
    }

    public function field(string $property): Field
    {
        foreach ($this->fields as $field) {
            if ($field->property === $property) {
                return $field;
            }
        }

        throw new InvalidArgumentException(sprintf('%s has no property "%s".', $this->class, $property));
    }

    public function fieldByColumn(string $column): Field
    {
        foreach ($this->fields as $field) {
            if ($field->column === $column) {
                return $field;
            }
        }

        throw new InvalidArgumentException(sprintf('%s has no column "%s".', $this->table, $column));
    }

    public function columnOf(string $property): string
    {
        return $this->field($property)->column;
    }

    public function propertyOf(string $column): string
    {
        return $this->fieldByColumn($column)->property;
    }

    private function withIndex(Index $index): self
    {
        return new self($this->table, $this->class, $this->fields, [...$this->indexes, $index], $this->references);
    }

    /**
     * @param list<string> $columns
     */
    private function indexName(array $columns, string $suffix): string
    {
        return sprintf('%s_%s_%s', $this->table, implode('_', $columns), $suffix);
    }
}

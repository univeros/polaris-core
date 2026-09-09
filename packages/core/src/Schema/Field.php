<?php

declare(strict_types=1);

namespace Polaris\Schema;

use function preg_replace;
use function strtolower;

/**
 * One column and the model property it maps to. Immutable; the fluent methods return copies.
 */
final readonly class Field
{
    private function __construct(
        public string $property,
        public string $column,
        public FieldType $type,
        public ?int $length,
        public bool $nullable,
        public bool $primary,
        public bool $hasDefault,
        public mixed $default,
    ) {
    }

    public static function string(string $property, int $length, ?string $column = null): self
    {
        return self::make($property, $column, FieldType::String, $length);
    }

    public static function text(string $property, ?string $column = null): self
    {
        return self::make($property, $column, FieldType::Text);
    }

    public static function int(string $property, ?string $column = null): self
    {
        return self::make($property, $column, FieldType::Int);
    }

    public static function bool(string $property, ?string $column = null): self
    {
        return self::make($property, $column, FieldType::Bool);
    }

    public static function datetime(string $property, ?string $column = null): self
    {
        return self::make($property, $column, FieldType::DateTime);
    }

    public static function json(string $property, ?string $column = null): self
    {
        return self::make($property, $column, FieldType::Json);
    }

    public function primary(): self
    {
        return new self($this->property, $this->column, $this->type, $this->length, $this->nullable, true, $this->hasDefault, $this->default);
    }

    public function nullable(): self
    {
        return new self($this->property, $this->column, $this->type, $this->length, true, $this->primary, $this->hasDefault, $this->default);
    }

    public function default(mixed $value): self
    {
        return new self($this->property, $this->column, $this->type, $this->length, $this->nullable, $this->primary, true, $value);
    }

    public static function snakeCase(string $property): string
    {
        return strtolower((string) preg_replace('/(?<!^)[A-Z]/', '_$0', $property));
    }

    private static function make(string $property, ?string $column, FieldType $type, ?int $length = null): self
    {
        return new self($property, $column ?? self::snakeCase($property), $type, $length, false, false, false, null);
    }
}

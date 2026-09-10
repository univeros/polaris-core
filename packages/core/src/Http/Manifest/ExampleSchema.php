<?php

declare(strict_types=1);

namespace Polaris\Http\Manifest;

use function array_is_list;
use function array_key_exists;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use function count;
use function in_array;
use function is_array;
use function is_bool;
use function is_float;
use function is_int;
use function is_string;
use function sort;

/**
 * A JSON Schema inferred from a spec's `output.example`: the documented approximation that types the
 * responses in the OpenAPI document and in the generated TypeScript client (docs/adapters/spec.md §7).
 * Every key of an object example is required; scalars take their JSON type; the items of an array are
 * merged, so a key missing from some items is optional and a key null in some is nullable; a value that
 * is null wherever it appears is a nullable string; an empty array has untyped items. Several examples
 * (`example` and `example_<variant>`) become a `oneOf`.
 */
final class ExampleSchema
{
    /**
     * @param array<string, array<string, mixed>> $examples
     * @return array<string, mixed>
     */
    public static function fromExamples(array $examples): array
    {
        $schemas = array_values(array_map(self::fromValue(...), $examples));

        return count($schemas) === 1 ? $schemas[0] : ['oneOf' => $schemas];
    }

    /**
     * @return array<string, mixed>
     */
    public static function fromValue(mixed $value): array
    {
        return self::finish(self::infer($value));
    }

    /**
     * @return array<string, mixed>
     */
    private static function infer(mixed $value): array
    {
        if (is_array($value)) {
            return array_is_list($value) ? self::list($value) : self::object($value);
        }
        if (is_bool($value)) {
            return ['type' => 'boolean'];
        }
        if (is_int($value)) {
            return ['type' => 'integer'];
        }
        if (is_float($value)) {
            return ['type' => 'number'];
        }
        if (is_string($value)) {
            return ['type' => 'string'];
        }

        return ['type' => 'null'];
    }

    /**
     * @param array<string, mixed> $object
     * @return array<string, mixed>
     */
    private static function object(array $object): array
    {
        $properties = [];
        foreach ($object as $key => $value) {
            $properties[(string) $key] = self::infer($value);
        }
        $schema = ['type' => 'object', 'properties' => $properties];
        if ($properties !== []) {
            $schema['required'] = array_keys($properties);
        }

        return $schema;
    }

    /**
     * @param list<mixed> $list
     * @return array<string, mixed>
     */
    private static function list(array $list): array
    {
        $merged = [];
        foreach ($list as $item) {
            $merged = self::merge($merged, self::infer($item));
        }

        return ['type' => 'array', 'items' => $merged];
    }

    /**
     * The schema of two sibling items: object properties are unioned and required only where both
     * require them, array items are merged, scalar types are unioned; an untyped side yields the other,
     * and shapes that disagree (an object against a scalar) yield an untyped schema.
     *
     * @param array<string, mixed> $a
     * @param array<string, mixed> $b
     * @return array<string, mixed>
     */
    private static function merge(array $a, array $b): array
    {
        if ($a === [] || $b === []) {
            return $a === [] ? $b : $a;
        }
        if ($a['type'] === 'object' && $b['type'] === 'object') {
            $properties = $a['properties'];
            foreach ($b['properties'] as $key => $schema) {
                $properties[$key] = array_key_exists($key, $properties) ? self::merge($properties[$key], $schema) : $schema;
            }
            $required = array_values(array_filter($a['required'] ?? [], static fn(string $key): bool => in_array($key, $b['required'] ?? [], true)));
            $schema = ['type' => 'object', 'properties' => $properties];
            if ($required !== []) {
                $schema['required'] = $required;
            }

            return $schema;
        }
        if ($a['type'] === 'array' && $b['type'] === 'array') {
            return ['type' => 'array', 'items' => self::merge($a['items'], $b['items'])];
        }
        $types = array_values(array_unique([...(array) $a['type'], ...(array) $b['type']]));
        if (in_array('object', $types, true) || in_array('array', $types, true)) {
            return [];
        }
        sort($types);

        return ['type' => count($types) === 1 ? $types[0] : $types];
    }

    /**
     * A value that was null wherever the example showed it is typed as a nullable string.
     *
     * @param array<string, mixed> $schema
     * @return array<string, mixed>
     */
    private static function finish(array $schema): array
    {
        if (($schema['type'] ?? null) === 'null') {
            return ['type' => ['string', 'null']];
        }
        if (isset($schema['properties'])) {
            $schema['properties'] = array_map(self::finish(...), $schema['properties']);
        }
        if (isset($schema['items'])) {
            $schema['items'] = self::finish($schema['items']);
        }

        return $schema;
    }
}

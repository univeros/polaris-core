<?php

declare(strict_types=1);

namespace Polaris\Scim;

use function count;
use function in_array;
use function is_string;
use function preg_match_all;
use function str_contains;
use function str_starts_with;
use function strtolower;
use function stripslashes;
use function trim;

/**
 * The subset of SCIM filters a directory sends when it looks a resource up: `attr eq "value"`, `co`,
 * `sw`, joined by `and`; attributes compared case-insensitively. Anything else is `invalidFilter`.
 *
 * @phpstan-type Clause array{string, string, string}
 */
final readonly class Filter
{
    private const array OPERATORS = ['eq', 'co', 'sw'];

    /**
     * @param list<Clause> $clauses
     */
    private function __construct(public array $clauses)
    {
    }

    /**
     * @throws ScimError
     */
    public static function parse(?string $filter): self
    {
        $filter = $filter === null ? '' : trim($filter);
        if ($filter === '') {
            return new self([]);
        }
        $matched = preg_match_all('/([A-Za-z][A-Za-z0-9_.]*(?:\[[^\]]*\])?)\s+(eq|co|sw)\s+"((?:[^"\\\\]|\\\\.)*)"(?:\s+and\s+|$)/i', $filter, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        if ($matched === false || $matched === 0) {
            throw ScimError::invalid('The filter is not supported: use attr eq|co|sw "value", joined by and.', ScimError::INVALID_FILTER);
        }
        $consumed = 0;
        $clauses = [];
        foreach ($matches as $match) {
            if ($match[0][1] !== $consumed) {
                throw ScimError::invalid('The filter is not supported: use attr eq|co|sw "value", joined by and.', ScimError::INVALID_FILTER);
            }
            $consumed += strlen($match[0][0]);
            $attribute = strtolower(str_starts_with(strtolower($match[1][0]), 'emails') ? 'emails' : $match[1][0]);
            $clauses[] = [$attribute, strtolower($match[2][0]), stripslashes($match[3][0])];
        }
        if ($consumed !== strlen($filter)) {
            throw ScimError::invalid('The filter is not supported: use attr eq|co|sw "value", joined by and.', ScimError::INVALID_FILTER);
        }

        return new self($clauses);
    }

    /**
     * Whether a resource (its attributes flattened: `username`, `emails`, `externalid`, `displayname`,
     * ...) matches every clause.
     *
     * @param array<string, mixed> $attributes lower-case attribute => string value(s)
     */
    public function matches(array $attributes): bool
    {
        foreach ($this->clauses as [$attribute, $operator, $expected]) {
            $values = $attributes[$attribute] ?? null;
            $values = is_string($values) ? [$values] : (is_array($values) ? $values : []);
            $hit = false;
            foreach ($values as $value) {
                if (!is_string($value)) {
                    continue;
                }
                $hit = $hit || match ($operator) {
                    'eq' => strtolower($value) === strtolower($expected),
                    'co' => str_contains(strtolower($value), strtolower($expected)),
                    default => str_starts_with(strtolower($value), strtolower($expected)),
                };
            }
            if (!$hit) {
                return false;
            }
        }

        return true;
    }

    /**
     * The value an `eq` clause on the attribute asks for; null when the filter has none.
     */
    public function equals(string $attribute): ?string
    {
        foreach ($this->clauses as [$candidate, $operator, $value]) {
            if ($candidate === $attribute && $operator === 'eq') {
                return $value;
            }
        }

        return null;
    }

    public function isEmpty(): bool
    {
        return count($this->clauses) === 0 || !in_array($this->clauses[0][1], self::OPERATORS, true);
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Model\Grant;

use function array_key_exists;
use function array_values;
use function ceil;
use function count;
use function gettype;
use function in_array;
use function is_array;
use function is_float;
use function is_int;
use function is_numeric;
use function is_scalar;
use function is_string;
use function preg_match;
use function sprintf;
use function strlen;

use const PHP_INT_MAX;

/**
 * The constraints a grant puts on a capability's arguments, with AAP's operators per argument (`max`,
 * `min`, `in`, `not_in`) plus `pattern`, and the `budget` (`{count}` or `{amount, field}`, with an
 * optional `window` in seconds that becomes the grant's lifetime). An unknown operator is refused
 * (`agents/unknown_constraint_operator`); a violation names the argument, the operator and the value.
 */
final class Constraints
{
    public const array OPERATORS = ['max', 'min', 'in', 'not_in', 'pattern'];
    public const string BUDGET = 'budget';
    private const int MAX_FIELDS = 50;
    private const int MAX_LIST = 200;
    private const int MAX_PATTERN = 500;

    private function __construct()
    {
    }

    /**
     * The constraints an agent or an owner wrote, validated: the per-argument operators and the budget.
     *
     * @param array<mixed> $raw
     * @return array{fields: array<string, array<string, mixed>>, budget: array{kind: string, total: int, field: string|null, window: int|null}|null}
     * @throws AgentException `unknown_constraint_operator`, `invalid_input`
     */
    public static function parse(array $raw): array
    {
        if (count($raw) > self::MAX_FIELDS) {
            throw new AgentException(AgentException::INVALID_INPUT, sprintf('At most %d arguments may be constrained.', self::MAX_FIELDS));
        }
        $fields = [];
        $budget = null;
        foreach ($raw as $field => $operators) {
            if ($field === self::BUDGET) {
                $budget = is_array($operators) ? self::budget($operators) : throw new AgentException(AgentException::INVALID_INPUT, 'budget is an object: {count} or {amount, field}, with an optional window.');
                continue;
            }
            if (!is_string($field) || preg_match('/^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/', $field) !== 1 || !is_array($operators)) {
                throw new AgentException(AgentException::INVALID_INPUT, 'Constraints map an argument name to an object of operators.');
            }
            $fields[$field] = [];
            foreach ($operators as $operator => $value) {
                if (!is_string($operator) || !in_array($operator, self::OPERATORS, true)) {
                    throw new AgentException(AgentException::UNKNOWN_CONSTRAINT_OPERATOR, sprintf('Unknown constraint operator "%s" on "%s"; known: max, min, in, not_in, pattern, and budget.', is_string($operator) ? $operator : '?', $field));
                }
                $fields[$field][$operator] = self::operand($field, $operator, $value);
            }
        }

        return ['fields' => $fields, 'budget' => $budget];
    }

    /**
     * A budget specification, validated: `{count: N}` or `{amount: N, field: name}`, `window` seconds.
     *
     * @param array<string, mixed> $spec
     * @return array{kind: string, total: int, field: string|null, window: int|null}
     * @throws AgentException `invalid_input`
     */
    public static function budget(array $spec): array
    {
        $count = $spec[Grant::BUDGET_COUNT] ?? null;
        $amount = $spec[Grant::BUDGET_AMOUNT] ?? null;
        $field = $spec['field'] ?? null;
        $window = $spec['window'] ?? null;
        if (($count === null) === ($amount === null)) {
            throw new AgentException(AgentException::INVALID_INPUT, 'A budget is {count: N} or {amount: N, field: argument}.');
        }
        $total = $count ?? $amount;
        if (!is_int($total) || $total < 1 || $total > PHP_INT_MAX / 2) {
            throw new AgentException(AgentException::INVALID_INPUT, 'A budget total is a positive integer.');
        }
        if ($amount !== null && (!is_string($field) || preg_match('/^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/', $field) !== 1)) {
            throw new AgentException(AgentException::INVALID_INPUT, 'An amount budget names the argument it sums (field).');
        }
        if ($window !== null && (!is_int($window) || $window < 1)) {
            throw new AgentException(AgentException::INVALID_INPUT, 'A budget window is a positive number of seconds.');
        }

        return ['kind' => $count !== null ? Grant::BUDGET_COUNT : Grant::BUDGET_AMOUNT, 'total' => $total, 'field' => $amount === null ? null : $field, 'window' => $window];
    }

    /**
     * What the arguments violate: `[{field, constraint, actual}]`, empty when they satisfy every
     * constraint. A constrained argument that is absent is a violation: the constraint exists to bound it.
     *
     * @param array<string, array<string, mixed>> $fields
     * @param array<string, mixed> $arguments
     * @return list<array{field: string, constraint: string, actual: mixed}>
     */
    public static function violations(array $fields, array $arguments): array
    {
        $violations = [];
        foreach ($fields as $field => $operators) {
            $present = array_key_exists($field, $arguments);
            $actual = $arguments[$field] ?? null;
            foreach ($operators as $operator => $operand) {
                if (!$present || !self::satisfies($operator, $operand, $actual)) {
                    $violations[] = ['field' => $field, 'constraint' => $operator, 'actual' => is_scalar($actual) || $actual === null ? $actual : '<' . gettype($actual) . '>'];
                }
            }
        }

        return $violations;
    }

    /**
     * The cost of an execution against a budget: one for a count, the (rounded-up) value of the budget's
     * argument for an amount.
     *
     * @param array<string, mixed> $arguments
     * @throws AgentException `invalid_arguments` when the amount argument is not a non-negative number
     */
    public static function cost(Grant $grant, array $arguments): int
    {
        if ($grant->budgetKind !== Grant::BUDGET_AMOUNT) {
            return 1;
        }
        $value = $arguments[(string) $grant->budgetField] ?? null;
        if (!is_int($value) && !is_float($value) || $value < 0 || $value > PHP_INT_MAX / 2) {
            throw new AgentException(AgentException::INVALID_ARGUMENTS, sprintf('The budget argument "%s" must be a non-negative number.', (string) $grant->budgetField));
        }

        return (int) ceil($value);
    }

    private static function satisfies(string $operator, mixed $operand, mixed $actual): bool
    {
        return match ($operator) {
            'max' => is_numeric($actual) && $actual <= $operand,
            'min' => is_numeric($actual) && $actual >= $operand,
            'in' => is_scalar($actual) && in_array($actual, (array) $operand, true),
            'not_in' => is_scalar($actual) && !in_array($actual, (array) $operand, true),
            'pattern' => is_string($actual) && @preg_match('/^(?:' . $operand . ')$/u', $actual) === 1,
            default => false,
        };
    }

    private static function operand(string $field, string $operator, mixed $value): mixed
    {
        $invalid = static fn(string $what): AgentException => new AgentException(AgentException::INVALID_INPUT, sprintf('Constraint "%s" on "%s" takes %s.', $operator, $field, $what));
        switch ($operator) {
            case 'max':
            case 'min':
                return is_int($value) || is_float($value) ? $value : throw $invalid('a number');
            case 'in':
            case 'not_in':
                if (!is_array($value) || count($value) > self::MAX_LIST) {
                    throw $invalid('a list of scalars');
                }
                foreach ($value as $item) {
                    if (!is_scalar($item)) {
                        throw $invalid('a list of scalars');
                    }
                }

                return array_values($value);
            default:
                if (!is_string($value) || $value === '' || strlen($value) > self::MAX_PATTERN || @preg_match('/^(?:' . $value . ')$/u', '') === false) {
                    throw $invalid('a valid regular expression');
                }

                return $value;
        }
    }
}

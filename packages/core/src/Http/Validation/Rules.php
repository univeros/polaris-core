<?php

declare(strict_types=1);

namespace Polaris\Http\Validation;

use Polaris\Http\Manifest\FieldSpec;

use function array_key_exists;
use function explode;
use function filter_var;
use function in_array;
use function is_string;
use function mb_strlen;
use function preg_match;
use function sprintf;

use const FILTER_VALIDATE_EMAIL;

/**
 * The rule vocabulary the 52 specs use. `password_policy` and `suspended` are business rules the
 * services enforce; they parse but do not evaluate here.
 */
final class Rules
{
    /**
     * @param list<FieldSpec> $fields
     * @param array<string, mixed> $data
     * @return list<string> violation messages, empty when the data satisfies every rule
     */
    public static function violations(array $fields, array $data): array
    {
        $violations = [];
        foreach ($fields as $field) {
            $present = array_key_exists($field->name, $data) && $data[$field->name] !== null && $data[$field->name] !== '';
            $value = $data[$field->name] ?? null;
            foreach ($field->rules as $rule) {
                $message = self::check($rule, $field->name, $present, $value);
                if ($message !== null) {
                    $violations[] = $message;
                    break;
                }
            }
        }

        return $violations;
    }

    private static function check(Rule $rule, string $field, bool $present, mixed $value): ?string
    {
        if ($rule->name === 'required') {
            return $present ? null : sprintf('%s is required.', $field);
        }
        if (!$present) {
            return null;
        }

        return match ($rule->name) {
            'string' => is_string($value) ? null : sprintf('%s must be a string.', $field),
            'email' => is_string($value) && filter_var($value, FILTER_VALIDATE_EMAIL) !== false ? null : sprintf('%s must be a valid email address.', $field),
            'max' => is_string($value) && mb_strlen($value) <= (int) $rule->argument ? null : sprintf('%s must be at most %d characters.', $field, (int) $rule->argument),
            'in' => in_array($value, explode(',', (string) $rule->argument), true) ? null : sprintf('%s must be one of %s.', $field, (string) $rule->argument),
            'regex' => is_string($value) && preg_match((string) $rule->argument, $value) === 1 ? null : sprintf('%s has an invalid format.', $field),
            'e164' => is_string($value) && preg_match('/^\+[1-9]\d{1,14}$/', $value) === 1 ? null : sprintf('%s must be an E.164 phone number.', $field),
            default => null,
        };
    }
}

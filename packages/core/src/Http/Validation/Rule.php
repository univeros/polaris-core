<?php

declare(strict_types=1);

namespace Polaris\Http\Validation;

use InvalidArgumentException;

use function in_array;
use function sprintf;
use function str_contains;

/**
 * One parsed rule from a spec's `rules` list: a name and its optional argument.
 */
final readonly class Rule
{
    public const array NAMES = ['required', 'optional', 'string', 'email', 'max', 'in', 'regex', 'password_policy', 'e164', 'suspended'];

    private function __construct(public string $name, public ?string $argument)
    {
    }

    public static function parse(string $rule): self
    {
        $name = $rule;
        $argument = null;
        if (str_contains($rule, ':')) {
            [$name, $argument] = explode(':', $rule, 2);
        }
        if (!in_array($name, self::NAMES, true)) {
            throw new InvalidArgumentException(sprintf('Unknown validation rule "%s".', $rule));
        }
        if (in_array($name, ['max', 'in', 'regex'], true) && ($argument === null || $argument === '')) {
            throw new InvalidArgumentException(sprintf('Rule "%s" needs an argument.', $name));
        }

        return new self($name, $argument);
    }
}

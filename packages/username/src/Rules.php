<?php

declare(strict_types=1);

namespace Polaris\Username;

use function mb_strlen;
use function mb_strtolower;
use function preg_match;
use function sprintf;

/**
 * What a username may be: a length, a pattern and the names nobody may take. The defaults allow ASCII
 * letters, digits, `_` and `.`, 3 to 30 characters.
 */
final readonly class Rules
{
    public const array RESERVED = ['admin', 'administrator', 'root', 'system', 'support', 'help', 'polaris', 'anonymous', 'null', 'undefined', 'me'];

    /**
     * @param list<string> $reserved compared without regard to case
     */
    public function __construct(
        public int $minLength = 3,
        public int $maxLength = 30,
        public string $pattern = '/^[A-Za-z0-9_.]+$/',
        public array $reserved = self::RESERVED,
    ) {
    }

    /**
     * The username as stored for uniqueness.
     */
    public static function normalize(string $username): string
    {
        return mb_strtolower($username, 'UTF-8');
    }

    /**
     * @return list<string> what is wrong with it, empty when it is acceptable
     */
    public function violations(string $username): array
    {
        $errors = [];
        $length = mb_strlen($username, 'UTF-8');
        if ($length < $this->minLength || $length > $this->maxLength) {
            $errors[] = sprintf('The username must be %d to %d characters long.', $this->minLength, $this->maxLength);
        }
        if (preg_match($this->pattern, $username) !== 1) {
            $errors[] = 'The username contains characters that are not allowed.';
        }
        foreach ($this->reserved as $name) {
            if (self::normalize($name) === self::normalize($username)) {
                $errors[] = 'The username is reserved.';
                break;
            }
        }

        return $errors;
    }
}

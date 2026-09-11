<?php

declare(strict_types=1);

namespace Polaris\Audit\Retention;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;

use function is_array;
use function is_string;
use function sprintf;

/**
 * How long events are kept: a default ISO-8601 duration (`P90D`) and longer or shorter ones per
 * name; drains are the way to keep more.
 */
final class RetentionPolicy
{
    public const string DEFAULT = 'P90D';

    /**
     * @param array<string, string> $names name => duration
     */
    public function __construct(private readonly string $default = self::DEFAULT, private readonly array $names = [])
    {
        self::interval($this->default);
        foreach ($this->names as $duration) {
            self::interval($duration);
        }
    }

    /**
     * `['default' => 'P90D', 'names' => ['user.deleted' => 'P7Y']]`.
     *
     * @param array<string, mixed> $config
     */
    public static function fromArray(array $config): self
    {
        $default = $config['default'] ?? self::DEFAULT;
        $names = $config['names'] ?? [];
        if (!is_string($default) || !is_array($names)) {
            throw new InvalidArgumentException('retention takes a default duration and a names map.');
        }

        return new self($default, $names);
    }

    public function keepUntil(string $name, DateTimeImmutable $now): DateTimeImmutable
    {
        return $now->sub(self::interval($this->names[$name] ?? $this->default));
    }

    /**
     * The names with a retention of their own.
     *
     * @return list<string>
     */
    public function overridden(): array
    {
        return array_keys($this->names);
    }

    private static function interval(string $duration): DateInterval
    {
        try {
            return new DateInterval($duration);
        } catch (\Exception) {
            throw new InvalidArgumentException(sprintf('"%s" is not an ISO-8601 duration.', $duration));
        }
    }
}

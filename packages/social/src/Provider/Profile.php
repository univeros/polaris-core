<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use function mb_substr;
use function trim;

/**
 * Who the provider says the user is: its stable subject, the email it reports and whether it vouches
 * for it, the display name, and what else is worth keeping (`picture`, a handle).
 */
final readonly class Profile
{
    private const int MAX_NAME = 120;

    /**
     * @param array<string, mixed> $extra
     */
    public ?string $name;

    public function __construct(
        public string $subject,
        public ?string $email = null,
        public bool $emailVerified = false,
        ?string $name = null,
        public array $extra = [],
    ) {
        // What a provider (or Apple's user-typed form field) calls the user fits core's display name.
        $name = $name === null ? null : trim(mb_substr($name, 0, self::MAX_NAME));
        $this->name = $name === '' ? null : $name;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return ['name' => $this->name, ...$this->extra];
    }
}

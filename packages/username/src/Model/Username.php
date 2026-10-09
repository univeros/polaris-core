<?php

declare(strict_types=1);

namespace Polaris\Username\Model;

use DateTimeImmutable;

/**
 * A user's username (`polaris_username`): `username` is the lowercased form uniqueness is checked on,
 * `displayUsername` the form the user typed.
 */
final class Username
{
    public string $userId = '';
    public string $username = '';
    public string $displayUsername = '';
    public DateTimeImmutable $createdAt;
    public DateTimeImmutable $updatedAt;

    /**
     * @return array{username: string, display_username: string}
     */
    public function toArray(): array
    {
        return ['username' => $this->username, 'display_username' => $this->displayUsername];
    }
}

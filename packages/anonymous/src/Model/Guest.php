<?php

declare(strict_types=1);

namespace Polaris\Anonymous\Model;

use DateTimeImmutable;

/**
 * A guest (`polaris_anonymous`): a core user without a password whose email is a placeholder; once
 * converted, `convertedUserId` names the account the guest became.
 */
final class Guest
{
    public string $userId = '';
    public DateTimeImmutable $createdAt;
    public ?DateTimeImmutable $convertedAt = null;
    public ?string $convertedUserId = null;
}

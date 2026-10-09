<?php

declare(strict_types=1);

namespace Polaris\Passwordless\Model;

use DateTimeImmutable;

/**
 * A user's verified phone (`polaris_passwordless_phone`): a second contact and a sign-in identifier,
 * never a sign-up one.
 */
final class Phone
{
    public string $userId = '';
    public string $e164 = '';
    public DateTimeImmutable $verifiedAt;
    public DateTimeImmutable $createdAt;
}

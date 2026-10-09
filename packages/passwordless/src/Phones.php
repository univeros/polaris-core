<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use Polaris\Contract\DatabaseAdapter;
use Psr\Clock\ClockInterface;

/**
 * The verified phones: one per user, each number once.
 */
final class Phones
{
    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    /**
     * The user a verified number belongs to.
     */
    public function owner(string $e164): ?string
    {
        $row = $this->database->findOne(Schema::PHONES, ['e164' => $e164]);

        return $row === null ? null : (string) $row['user_id'];
    }

    public function forUser(string $userId): ?string
    {
        $row = $this->database->findOne(Schema::PHONES, ['user_id' => $userId]);

        return $row === null ? null : (string) $row['e164'];
    }

    /**
     * Sets the user's verified phone (replacing the one they had).
     *
     * @throws PasswordlessException another user has the number
     */
    public function attach(string $userId, string $e164): void
    {
        $owner = $this->owner($e164);
        if ($owner !== null && $owner !== $userId) {
            throw new PasswordlessException(PasswordlessException::PHONE_TAKEN, 'Another account uses this phone number.');
        }
        $now = $this->clock->now();
        $this->database->transaction(function () use ($userId, $e164, $now): void {
            $this->database->delete(Schema::PHONES, ['user_id' => $userId]);
            $this->database->insert(Schema::PHONES, ['user_id' => $userId, 'e164' => $e164, 'verified_at' => $now, 'created_at' => $now]);
        });
    }
}

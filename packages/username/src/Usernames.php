<?php

declare(strict_types=1);

namespace Polaris\Username;

use DateTimeImmutable;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Username\Model\Username;
use Psr\Clock\ClockInterface;
use Throwable;

use function trim;

/**
 * The usernames: who has which, and setting one under the rules. A unique index on the lowercased form
 * is what makes uniqueness hold under concurrent writes; the lookup before it only gives the common
 * case a clean answer.
 */
final class Usernames
{
    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock, private readonly Rules $rules)
    {
    }

    public function forUser(string $userId): ?Username
    {
        $row = $this->database->findOne(Schema::USERNAMES, ['user_id' => $userId]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * The user a username belongs to, without regard to case.
     */
    public function userId(string $username): ?string
    {
        $row = $this->database->findOne(Schema::USERNAMES, ['username' => Rules::normalize(trim($username))]);

        return $row === null ? null : (string) $row['user_id'];
    }

    /**
     * Sets (or changes) the user's username; `$display` defaults to the username as typed.
     *
     * @throws UsernameException invalid under the rules, or another user's
     */
    public function set(string $userId, string $username, ?string $display = null): Username
    {
        $username = trim($username);
        $violations = $this->rules->violations($username);
        $display = $display === null || trim($display) === '' ? $username : trim($display);
        if (Rules::normalize($display) !== Rules::normalize($username)) {
            $violations[] = 'The display username must be the username with another case.';
        }
        if ($violations !== []) {
            throw new UsernameException(UsernameException::INVALID, $violations);
        }
        $normalized = Rules::normalize($username);
        $owner = $this->userId($normalized);
        if ($owner !== null && $owner !== $userId) {
            throw new UsernameException(UsernameException::TAKEN);
        }
        $now = $this->clock->now();
        $current = $this->forUser($userId);
        try {
            if ($current === null) {
                $this->database->insert(Schema::USERNAMES, ['user_id' => $userId, 'username' => $normalized, 'display_username' => $display, 'created_at' => $now, 'updated_at' => $now]);
            } else {
                $this->database->update(Schema::USERNAMES, ['user_id' => $userId], ['username' => $normalized, 'display_username' => $display, 'updated_at' => $now]);
            }
        } catch (Throwable $exception) {
            // The unique index refused a username another user took between the lookup and the write.
            $owner = $this->userId($normalized);
            if ($owner !== null && $owner !== $userId) {
                throw new UsernameException(UsernameException::TAKEN);
            }

            throw $exception;
        }

        return $this->forUser($userId) ?? throw new UsernameException(UsernameException::TAKEN);
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Username
    {
        $username = new Username();
        $username->userId = (string) $row['user_id'];
        $username->username = (string) $row['username'];
        $username->displayUsername = (string) $row['display_username'];
        $username->createdAt = self::datetime($row['created_at']);
        $username->updatedAt = self::datetime($row['updated_at']);

        return $username;
    }

    private static function datetime(mixed $value): DateTimeImmutable
    {
        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}

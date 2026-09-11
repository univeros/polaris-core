<?php

declare(strict_types=1);

namespace Polaris\Audit\Activity;

use DateTimeImmutable;
use Polaris\Audit\Schema;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Event\MfaStepUpCompleted;
use Polaris\Event\MfaVerified;
use Polaris\Event\OrganizationSwitched;
use Polaris\Event\TokenRefreshed;
use Polaris\Event\UserLoggedIn;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

use function is_string;

/**
 * `last_active_at` per user, from the events a live session produces (sign-in, refresh, MFA,
 * organization switch), written at most once per interval: the cache remembers the last write.
 */
final class ActivityTracker
{
    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly int $interval = 300,
    ) {
    }

    public function __invoke(object $event): void
    {
        $userId = match (true) {
            $event instanceof UserLoggedIn, $event instanceof TokenRefreshed, $event instanceof MfaVerified,
            $event instanceof MfaStepUpCompleted, $event instanceof OrganizationSwitched => $event->userId,
            default => null,
        };
        if ($userId === null) {
            return;
        }
        $key = 'polaris.audit.activity.' . $userId;
        if ($this->cache->get($key) !== null) {
            return;
        }
        $now = $this->clock->now();
        if ($this->database->update(Schema::ACTIVITY, ['user_id' => $userId], ['last_active_at' => $now]) === 0) {
            $this->database->insert(Schema::ACTIVITY, ['user_id' => $userId, 'last_active_at' => $now]);
        }
        $this->cache->set($key, $now->format(DATE_ATOM), $this->interval);
    }

    public function lastActiveAt(string $userId): ?DateTimeImmutable
    {
        $row = $this->database->findOne(Schema::ACTIVITY, ['user_id' => $userId]);
        $value = $row['last_active_at'] ?? null;
        if ($value instanceof DateTimeImmutable) {
            return $value;
        }

        return is_string($value) && $value !== '' ? new DateTimeImmutable($value) : null;
    }
}

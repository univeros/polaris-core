<?php

declare(strict_types=1);

namespace Polaris\Audit\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Audit\Activity\ActivityTracker;
use Polaris\Audit\Tests\Support\MutableClock;
use Polaris\Event\MfaVerified;
use Polaris\Event\TokenRefreshed;
use Polaris\Event\UserLoggedIn;
use Polaris\Event\UserRegistered;
use Polaris\Support\InMemoryCache;
use Polaris\Testing\InMemoryAdapter;

#[CoversClass(ActivityTracker::class)]
final class ActivityTrackerTest extends TestCase
{
    public function testWritesOncePerIntervalFromTheLiveSessionEvents(): void
    {
        $database = new InMemoryAdapter();
        $cache = new InMemoryCache();
        $clock = new MutableClock(new DateTimeImmutable('2026-09-11T10:00:00+00:00'));
        $tracker = new ActivityTracker($database, $cache, $clock, 300);

        $tracker(new UserRegistered('u1', 'ada@example.com', 'tok'));
        self::assertNull($tracker->lastActiveAt('u1'), 'registering is not activity');

        $tracker(new UserLoggedIn('u1', 's1'));
        self::assertSame('2026-09-11T10:00:00+00:00', self::at($tracker, 'u1'));

        $clock->advance('+1 minute');
        $tracker(new TokenRefreshed('u1', 'f1'));
        self::assertSame('2026-09-11T10:00:00+00:00', self::at($tracker, 'u1'), 'inside the interval: no write');

        $cache->clear();
        $clock->advance('+10 minutes');
        $tracker(new MfaVerified('u1', 'factor1'));
        self::assertSame('2026-09-11T10:11:00+00:00', self::at($tracker, 'u1'), 'after the interval: one row updated, not inserted twice');
        self::assertSame(1, $database->count('polaris_audit_activity', ['user_id' => 'u1']));
    }

    private static function at(ActivityTracker $tracker, string $userId): ?string
    {
        return $tracker->lastActiveAt($userId)?->format(DATE_ATOM);
    }
}

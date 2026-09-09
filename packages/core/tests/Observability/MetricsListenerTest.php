<?php

declare(strict_types=1);

namespace Polaris\Tests\Observability;

use Polaris\Tests\Support\RecordingMetrics;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Polaris\Event\RefreshReuseDetected;
use Polaris\Event\UserLoggedIn;
use Polaris\Event\UserLoginFailed;
use Polaris\Event\UserRegistered;
use Polaris\Observability\MetricsListener;

/**
 * Verifies the #42 {@see MetricsListener}: every Polaris domain event increments the
 * `polaris.auth.events` counter with its catalog name as the `event` attribute (alert rules
 * filter on it), unrelated objects are ignored, and the token on a secret-carrying event never
 * reaches a metric attribute.
 */
final class MetricsListenerTest extends TestCase
{
    private function recorder(): RecordingMetrics
    {
        return new RecordingMetrics();
    }

    public function testCountsEventsWithTheirCatalogName(): void
    {
        $recorder = $this->recorder();
        $listener = new MetricsListener($recorder, new NullLogger());

        $listener(new UserLoggedIn('user-1', 'session-1', '203.0.113.7'));
        $listener(new UserLoginFailed('user-1', '203.0.113.7'));
        $listener(new RefreshReuseDetected('user-1', 'family-1', null));

        $points = $recorder->metrics();
        self::assertCount(3, $points);
        self::assertSame('polaris.auth.events', $points[0]->name);
        self::assertSame(['event' => 'user.logged_in'], $points[0]->attributes);
        self::assertSame(['event' => 'user.login_failed'], $points[1]->attributes);
        self::assertSame(['event' => 'auth.refresh_reuse_detected'], $points[2]->attributes);
        self::assertSame(1.0, $points[0]->value);
    }

    public function testSecretCarryingEventsExposeOnlyTheirName(): void
    {
        $recorder = $this->recorder();
        $listener = new MetricsListener($recorder, new NullLogger());

        $listener(new UserRegistered('user-1', 'new@example.com', 'verification-secret-token'));

        $points = $recorder->metrics();
        self::assertCount(1, $points);
        self::assertSame(['event' => 'user.registered'], $points[0]->attributes);
    }

    public function testIgnoresObjectsOutsideTheEventNamespace(): void
    {
        $recorder = $this->recorder();
        $listener = new MetricsListener($recorder, new NullLogger());

        $listener(new class () {
            public const string NAME = 'not.a.polaris.event';
        });

        self::assertCount(0, $recorder->metrics());
    }
}

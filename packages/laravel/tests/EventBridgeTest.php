<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use Illuminate\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Polaris\Laravel\Events\EventBridge;
use stdClass;

#[CoversClass(EventBridge::class)]
final class EventBridgeTest extends TestCase
{
    public function testRunsThePolarisListenersThenLaravels(): void
    {
        $seen = [];
        $events = new Dispatcher();
        $events->listen(stdClass::class, static function (object $event) use (&$seen): void {
            $seen[] = 'laravel';
        });
        $listeners = [static function (object $event) use (&$seen): void {
            $seen[] = 'polaris';
        }];
        $bridge = new EventBridge($events, static fn (): array => $listeners);
        $event = new stdClass();

        self::assertSame($event, $bridge->dispatch($event));
        self::assertSame(['polaris', 'laravel'], $seen);
    }
}

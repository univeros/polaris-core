<?php

declare(strict_types=1);

namespace Polaris\Laravel\Events;

use Closure;
use Illuminate\Contracts\Events\Dispatcher;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The PSR-14 dispatcher Polaris gets in Laravel: every event runs the Polaris listeners (audit log,
 * notifications, metrics), then goes through Laravel's dispatcher, so `Event::listen(UserRegistered::class, ...)`
 * works as for any application event. The listeners are resolved lazily because they come from the
 * graph this dispatcher is part of.
 */
final readonly class EventBridge implements EventDispatcherInterface
{
    /**
     * @param Closure(): list<callable(object): void> $listeners
     */
    public function __construct(private Dispatcher $events, private Closure $listeners)
    {
    }

    #[Override]
    public function dispatch(object $event): object
    {
        foreach (($this->listeners)() as $listener) {
            $listener($event);
        }
        $this->events->dispatch($event);

        return $event;
    }
}

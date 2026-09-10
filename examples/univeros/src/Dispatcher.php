<?php

declare(strict_types=1);

namespace PolarisDemo;

use Override;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The smallest PSR-14 dispatcher: every listener sees every event.
 */
final class Dispatcher implements EventDispatcherInterface
{
    /** @var list<callable(object): void> */
    private array $listeners = [];

    public function listen(callable $listener): void
    {
        $this->listeners[] = $listener;
    }

    #[Override]
    public function dispatch(object $event): object
    {
        foreach ($this->listeners as $listener) {
            $listener($event);
        }

        return $event;
    }
}

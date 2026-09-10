<?php

declare(strict_types=1);

namespace Polaris\Symfony\Event;

use Override;
use Polaris\Polaris;
use Psr\EventDispatcher\EventDispatcherInterface;
use ReflectionClass;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

use function basename;
use function class_exists;
use function dirname;
use function glob;
use function is_subclass_of;

/**
 * Subscribes the Polaris listeners (audit log, notifications, metrics) to Symfony's dispatcher, which
 * is PSR-14 and dispatches by event class: one subscription per event class in `Polaris\Event`.
 * The application's own `#[AsEventListener(UserRegistered::class)]` listeners work as usual.
 */
final readonly class PolarisEventSubscriber implements EventSubscriberInterface
{
    public function __construct(private Polaris $polaris)
    {
    }

    /**
     * @return array<class-string, string>
     */
    #[Override]
    public static function getSubscribedEvents(): array
    {
        $events = [];
        $directory = dirname((string) (new ReflectionClass(Polaris::class))->getFileName()) . '/Event';
        foreach (glob($directory . '/*.php') ?: [] as $file) {
            $class = 'Polaris\\Event\\' . basename($file, '.php');
            if (class_exists($class) && !is_subclass_of($class, EventDispatcherInterface::class)) {
                $events[$class] = 'onPolarisEvent';
            }
        }

        return $events;
    }

    public function onPolarisEvent(object $event): void
    {
        foreach ($this->polaris->listeners() as $listener) {
            $listener($event);
        }
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Yii\Event;

use Polaris\Polaris;
use Psr\EventDispatcher\EventDispatcherInterface;
use ReflectionClass;

use function basename;
use function class_exists;
use function dirname;
use function glob;
use function is_subclass_of;

/**
 * The `events-web` / `events-console` configuration: `yiisoft/yii-event` dispatches by exact event
 * class, so {@see PolarisListener} is registered for every class in `Polaris\Event` (listed from the
 * directory), and the application's own listeners for those classes keep working.
 */
final class Events
{
    /**
     * @return array<class-string, list<class-string>>
     */
    public static function listeners(): array
    {
        $events = [];
        $directory = dirname((string) (new ReflectionClass(Polaris::class))->getFileName()) . '/Event';
        foreach (glob($directory . '/*.php') ?: [] as $file) {
            $class = 'Polaris\\Event\\' . basename($file, '.php');
            if (class_exists($class) && !is_subclass_of($class, EventDispatcherInterface::class)) {
                $events[$class] = [PolarisListener::class];
            }
        }

        return $events;
    }
}

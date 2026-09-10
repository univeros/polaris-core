<?php

declare(strict_types=1);

namespace Polaris\Yii\Event;

use Polaris\Polaris;

/**
 * Runs the Polaris listeners (audit log, notifications, metrics) for one event dispatched by the
 * application's dispatcher.
 */
final readonly class PolarisListener
{
    public function __construct(private Polaris $polaris)
    {
    }

    public function __invoke(object $event): void
    {
        foreach ($this->polaris->listeners() as $listener) {
            $listener($event);
        }
    }
}

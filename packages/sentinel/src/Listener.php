<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use Polaris\Event\UserLoggedIn;
use Polaris\Event\UserLoginFailed;
use Polaris\Sentinel\Provider\GeoResolver;
use Polaris\Sentinel\Signal\CredentialStuffing;

/**
 * The outcomes the engine cannot see at attempt time: a failed sign-in feeds the credential-stuffing
 * ratio; a sign-in records the device of the request in flight, with its address and location.
 */
final class Listener
{
    public function __construct(private readonly Engine $engine, private readonly Devices $devices, private readonly GeoResolver $geo)
    {
    }

    public function __invoke(object $event): void
    {
        if ($event instanceof UserLoginFailed) {
            $this->engine->signal(CredentialStuffing::class)?->failed($event->ip);

            return;
        }
        if ($event instanceof UserLoggedIn) {
            $deviceId = $this->engine->current?->deviceId;
            if ($deviceId !== null) {
                $this->devices->record($event->userId, $deviceId, $event->ip, $event->ip === null ? null : $this->geo->resolve($event->ip));
            }
        }
    }
}

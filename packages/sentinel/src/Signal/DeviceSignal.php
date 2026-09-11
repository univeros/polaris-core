<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Signal;

use Override;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\Devices;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Verdict;

/**
 * A sign-in from a device the user never signed in from (the device cookie is missing or unknown),
 * once they have at least one known device.
 */
final class DeviceSignal implements Signal
{
    public const string NAME = 'device';

    public function __construct(private readonly Devices $devices, private readonly UserRepository $users, private readonly int $score = 40)
    {
    }

    #[Override]
    public function name(): string
    {
        return self::NAME;
    }

    #[Override]
    public function evaluate(Attempt $attempt): Verdict
    {
        if ($attempt->kind !== Attempt::SIGN_IN || $attempt->email === null) {
            return Verdict::silent(self::NAME);
        }
        $user = $this->users->findOneBy(['email' => $attempt->email]);
        if (!$user instanceof User || $this->devices->countFor($user->id) === 0) {
            return Verdict::silent(self::NAME);
        }
        if ($attempt->deviceId !== null && $this->devices->find($user->id, $attempt->deviceId) !== null) {
            return Verdict::silent(self::NAME);
        }

        return new Verdict(self::NAME, $this->score, [$attempt->deviceId === null ? 'no device cookie' : 'unknown device']);
    }
}

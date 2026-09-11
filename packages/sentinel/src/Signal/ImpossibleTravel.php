<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Signal;

use Override;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\Devices;
use Polaris\Sentinel\Provider\GeoResolver;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Verdict;
use Psr\Clock\ClockInterface;

use function max;
use function sprintf;

/**
 * A sign-in from a place the user could not have reached since their last one: the distance between the
 * last recorded location and this address's, over the time elapsed, above a speed.
 */
final class ImpossibleTravel implements Signal
{
    public const string NAME = 'impossible_travel';

    public function __construct(
        private readonly GeoResolver $geo,
        private readonly Devices $devices,
        private readonly UserRepository $users,
        private readonly ClockInterface $clock,
        private readonly float $maxKmh = 900.0,
        private readonly int $score = 70,
    ) {
    }

    #[Override]
    public function name(): string
    {
        return self::NAME;
    }

    #[Override]
    public function evaluate(Attempt $attempt): Verdict
    {
        if ($attempt->kind !== Attempt::SIGN_IN || $attempt->email === null || $attempt->ip === null) {
            return Verdict::silent(self::NAME);
        }
        $here = $this->geo->resolve($attempt->ip);
        $user = $here === null ? null : $this->users->findOneBy(['email' => $attempt->email]);
        $last = $user instanceof User ? $this->devices->latest($user->id) : null;
        $there = $last === null ? null : Devices::location($last);
        if ($here === null || $last === null || $there === null) {
            return Verdict::silent(self::NAME);
        }
        $km = $there->distanceTo($here);
        $hours = max(1 / 60, ($this->clock->now()->getTimestamp() - $last->lastSeenAt->getTimestamp()) / 3600);
        $kmh = $km / $hours;

        return $kmh > $this->maxKmh
            ? new Verdict(self::NAME, $this->score, [sprintf('%.0f km since the last sign-in %.1f h ago (%.0f km/h)', $km, $hours, $kmh)])
            : Verdict::silent(self::NAME);
    }
}

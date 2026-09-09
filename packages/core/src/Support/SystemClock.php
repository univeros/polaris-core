<?php

declare(strict_types=1);

namespace Polaris\Support;

use DateTimeImmutable;
use Override;
use Psr\Clock\ClockInterface;

final class SystemClock implements ClockInterface
{
    #[Override]
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Signal;

use Override;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\CounterStore;
use Polaris\Sentinel\Resettable;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Verdict;

use function sprintf;

/**
 * Attempts per IP, per email and per device in a window; each dimension over its limit adds the score,
 * so one runaway dimension challenges and two block.
 */
final class Velocity implements Signal, Resettable
{
    public const string NAME = 'velocity';

    /**
     * @param array<string, array{int, int}> $limits dimension (ip, email, device) => [limit, window seconds]
     */
    public function __construct(
        private readonly CounterStore $counters,
        private readonly array $limits = ['ip' => [20, 600], 'email' => [10, 600], 'device' => [30, 600]],
        private readonly int $score = 50,
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
        $score = 0;
        $reasons = [];
        foreach (['ip' => $attempt->ip, 'email' => $attempt->email, 'device' => $attempt->deviceId] as $dimension => $identifier) {
            if ($identifier === null || !isset($this->limits[$dimension])) {
                continue;
            }
            [$limit, $window] = $this->limits[$dimension];
            $count = $this->counters->increment(self::key($dimension, $identifier), $window);
            if ($count > $limit) {
                $score += $this->score;
                $reasons[] = sprintf('%s: %d attempts in %d s (limit %d)', $dimension, $count, $window, $limit);
            }
        }

        return new Verdict(self::NAME, $score, $reasons);
    }

    #[Override]
    public function reset(string $identifier): void
    {
        foreach ($this->limits as $dimension => [, $window]) {
            $this->counters->reset(self::key($dimension, $identifier), $window);
        }
    }

    private static function key(string $dimension, string $identifier): string
    {
        return sprintf('velocity:%s:%s', $dimension, $identifier);
    }
}

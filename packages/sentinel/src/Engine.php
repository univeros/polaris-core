<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Runs the signals over an attempt, lets the policy decide, records the decision when a signal spoke
 * (`polaris_sentinel_decision`, `sentinel.evaluated`). A signal that throws is skipped and logged: the
 * engine fails open. `current` is the attempt of the request in flight, for the listener.
 */
final class Engine
{
    public ?Attempt $current = null;

    /**
     * @param list<Signal> $signals
     */
    public function __construct(
        private readonly array $signals,
        private readonly Policy $policy,
        private readonly bool $enforce,
        private readonly Decisions $decisions,
        private readonly EventDispatcherInterface $events,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function evaluate(Attempt $attempt): Decision
    {
        $this->current = $attempt;
        $verdicts = [];
        foreach ($this->signals as $signal) {
            try {
                $verdicts[] = $signal->evaluate($attempt);
            } catch (Throwable $exception) {
                $this->logger->error('[polaris sentinel] signal {signal} failed: {reason}', ['signal' => $signal->name(), 'reason' => $exception->getMessage(), 'exception' => $exception]);
            }
        }
        $decision = $this->policy->decide($verdicts, $this->enforce);
        if ($decision->verdicts !== []) {
            $this->decisions->record($attempt, $decision);
            $this->events->dispatch(new SentinelEvaluated($attempt, $decision));
        }

        return $decision;
    }

    /**
     * Clears every resettable signal's counters for an identifier (an email or an address).
     */
    public function unblock(string $identifier): void
    {
        foreach ($this->signals as $signal) {
            if ($signal instanceof Resettable) {
                $signal->reset($identifier);
            }
        }
    }

    /**
     * @template T of Signal
     * @param class-string<T> $class
     * @return T|null
     */
    public function signal(string $class): ?Signal
    {
        foreach ($this->signals as $signal) {
            if ($signal instanceof $class) {
                return $signal;
            }
        }

        return null;
    }

    public function enforces(): bool
    {
        return $this->enforce;
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Audit\Sink;

use Override;
use Polaris\Audit\Model\AuditEvent;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Every configured sink, in order, fail-open: a sink that throws is logged and the others still run,
 * because an audit write must never break the operation it observes.
 */
final class SinkChain implements AuditSink
{
    /** @var list<AuditSink> */
    private readonly array $sinks;

    public function __construct(private readonly LoggerInterface $logger, AuditSink ...$sinks)
    {
        $this->sinks = $sinks;
    }

    #[Override]
    public function write(AuditEvent ...$events): void
    {
        foreach ($this->sinks as $sink) {
            try {
                $sink->write(...$events);
            } catch (Throwable $exception) {
                $this->logger->error('Audit sink {sink} failed: {reason}', ['sink' => $sink::class, 'reason' => $exception->getMessage(), 'exception' => $exception]);
            }
        }
    }
}

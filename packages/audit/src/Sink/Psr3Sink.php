<?php

declare(strict_types=1);

namespace Polaris\Audit\Sink;

use Override;
use Polaris\Audit\Model\AuditEvent;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * One log record per event, the event as context.
 */
final readonly class Psr3Sink implements AuditSink
{
    public function __construct(private LoggerInterface $logger, private string $level = LogLevel::INFO)
    {
    }

    #[Override]
    public function write(AuditEvent ...$events): void
    {
        foreach ($events as $event) {
            $this->logger->log($this->level, 'audit {name}', ['name' => $event->name, 'audit' => $event->toArray()]);
        }
    }
}

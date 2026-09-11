<?php

declare(strict_types=1);

namespace Polaris\Audit\Sink;

use Override;
use Polaris\Audit\Model\AuditEvent;
use RuntimeException;

use function file_put_contents;
use function json_encode;
use function sprintf;

use const FILE_APPEND;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const LOCK_EX;

/**
 * JSON lines, one event per line; for development and for a tail-based shipper.
 */
final readonly class FileSink implements AuditSink
{
    public function __construct(private string $path)
    {
    }

    #[Override]
    public function write(AuditEvent ...$events): void
    {
        $lines = '';
        foreach ($events as $event) {
            $lines .= json_encode($event->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
        }
        if ($lines !== '' && file_put_contents($this->path, $lines, FILE_APPEND | LOCK_EX) === false) {
            throw new RuntimeException(sprintf('Cannot append to the audit file %s.', $this->path));
        }
    }
}

<?php

declare(strict_types=1);

namespace Polaris\Support;

use Override;
use Polaris\Contract\MetricsInterface;
use Psr\Log\LoggerInterface;

/**
 * The default {@see MetricsInterface}: every counter increment is a PSR-3 debug record.
 */
final class LogMetrics implements MetricsInterface
{
    public function __construct(private readonly LoggerInterface $logger)
    {
    }

    #[Override]
    public function counter(string $name, float $value = 1.0, array $attributes = [], ?string $description = null): void
    {
        $this->logger->debug('metric {name} +{value}', ['name' => $name, 'value' => $value, 'attributes' => $attributes]);
    }
}

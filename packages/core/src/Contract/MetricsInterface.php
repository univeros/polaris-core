<?php

declare(strict_types=1);

namespace Polaris\Contract;

/**
 * Where Polaris counts its domain events. Bind your metrics client; the default logs at debug.
 */
interface MetricsInterface
{
    /**
     * @param array<string, string> $attributes
     */
    public function counter(string $name, float $value = 1.0, array $attributes = [], ?string $description = null): void;
}
